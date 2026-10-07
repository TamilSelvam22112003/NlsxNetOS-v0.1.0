import ipaddress
import logging
import select
import signal
import socket
import subprocess
import time
from dataclasses import dataclass

from nlsxnetos.router_ca import store as ca_store
from nlsxnetos.router_ca.client import RouterCAClient
from .config import PeerConfig, endpoint, load
from .encapsulation import HEADER, open_ip_packet, peek_ip_packet, seal_ip_packet
from .handshake import INIT, RESPONSE, decode_message, encode_message, initiator_key, new_init, responder_key
from .identity import load_or_create, public_key_b64, unb64
from .replay import ReplayWindow
from .rsa import load_or_create as load_rsa_private_key, max_plaintext_per_rsa_block
from .rsa_signing import load_or_create as load_rsa_signing_private_key, public_key_b64 as rsa_signing_public_key_b64
from .routing import install_tun_routes, remove_tun_routes, install_lan_policy, remove_lan_policy, lookup_route, wait_for_route
from .tun import TunDevice

LOG = logging.getLogger("nlsxnetos.nls")
MAX_DATAGRAM = 65535


@dataclass
class Session:
    peer_id: str
    endpoint: tuple
    session_id: bytes
    send_key: bytes
    recv_key: bytes
    peer_identity: bytes
    peer_encryption_public_key: str
    peer_signing_public_key: str
    recv_replay: ReplayWindow
    last_seen: float
    last_tx: float
    tx_sequence: int = 0


class NLSDaemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.identity = load_or_create(cfg.identity_key)
        self.identity_public = public_key_b64(self.identity)
        self.identity_raw = unb64(self.identity_public)
        self.encryption_private_key = load_rsa_private_key(cfg.encryption_private_key)
        self.signing_private_key = load_rsa_signing_private_key(cfg.signing_private_key)
        self.sock = None
        self.tun = None
        self.peers = {p.id: p for p in cfg.peers}
        self.sessions = {}
        self.pending = {}
        self.seen_handshakes = {}
        self.blocked = {}
        self.local_certificate = None
        self.local_ca_timestamp = None
        self.ca_client = (
            RouterCAClient(
                cfg.router_ca_server_url,
                cfg.router_ca_timeout_seconds,
                cfg.router_ca_ca_file or None,
                cfg.router_ca_bearer_token or None,
            )
            if cfg.router_ca_server_url
            else None
        )
        self.pending_payloads = {}
        self.forward_cache = {}
        self.max_pending_payloads = 64
        self.running = True
        self.stats = {
            "handshakes": 0,
            "established": 0,
            "rx": 0,
            "tx": 0,
            "drops": 0,
            "data_drops": 0,
        }

    def _blocked(self, peer_id):
        until = self.blocked.get(peer_id, 0)
        if until and until <= time.time():
            self.blocked.pop(peer_id, None)
            return False
        return until > time.time()

    def _block(self, peer_id, reason):
        self.blocked[peer_id] = time.time() + self.cfg.peer_block_seconds
        LOG.warning(
            "NLS peer %s temporarily blocked for %ss: %s",
            peer_id,
            self.cfg.peer_block_seconds,
            reason,
        )

    def _ca_entry_for_peer(self, peer):
        if peer.router_ca_id is None:
            return None
        if self.ca_client:
            try:
                return self.ca_client.get_router(peer.router_ca_id)
            except Exception as exc:
                LOG.warning("Router-CA lookup for peer %s failed: %s", peer.id, exc)
        return next((e for e in ca_store.load() if e.id == peer.router_ca_id), None)

    def _peer_trusted(self, peer):
        if self._blocked(peer.id):
            return False
        if peer.router_ca_id is None:
            return True
        entry = self._ca_entry_for_peer(peer)
        ok = bool(
            entry
            and entry.public_key
            and entry.public_key == peer.public_key
            and (not entry.endpoint or entry.endpoint == peer.endpoint)
            and entry.encryption_public_key
            and entry.encryption_public_key == peer.encryption_public_key
            and entry.signing_public_key
            and entry.signing_public_key == peer.signing_public_key
        )
        if not ok:
            LOG.warning("peer %s rejected: Router-CA identity/endpoint/key mismatch", peer.id)
        return ok

    def _validate_tun_mtu(self):
        if not self.cfg.bind_interface:
            return
        result = subprocess.run(
            ["ip", "-o", "link", "show", "dev", self.cfg.bind_interface],
            check=True,
            capture_output=True,
            text=True,
        )
        fields = result.stdout.split()
        try:
            mtu = int(fields[fields.index("mtu") + 1])
        except (ValueError, IndexError) as exc:
            raise RuntimeError("unable to determine NLS WAN interface MTU") from exc
        # RSA-only payloads are split into RSA-OAEP/SHA-256 blocks. For the
        # default 3072-bit key, each plaintext block is 318 bytes and each
        # ciphertext block is 384 bytes. Account for the NLS header and the
        # worst-case IPv6 + UDP transport header.
        rsa_block = max_plaintext_per_rsa_block(self.encryption_private_key)
        rsa_ciphertext = self.encryption_private_key.key_size // 8
        packet_blocks = (self.cfg.tun.mtu + rsa_block - 1) // rsa_block
        nls_size = HEADER.size + packet_blocks * rsa_ciphertext
        if nls_size + 40 + 8 > mtu:
            raise RuntimeError(
                f"NLS TUN MTU {self.cfg.tun.mtu} is too large for RSA-only transport "
                f"on {self.cfg.bind_interface}: requires {nls_size + 48} bytes, "
                f"WAN MTU is {mtu}; use a smaller nls tun mtu"
            )

    def _bind(self):
        family = socket.AF_INET6 if ":" in self.cfg.listen_address else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.cfg.bind_interface:
            if not hasattr(socket, "SO_BINDTODEVICE"):
                raise RuntimeError("SO_BINDTODEVICE is unavailable on this platform")
            self.sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                self.cfg.bind_interface.encode() + b"\\0",
            )
        self.sock.bind((self.cfg.listen_address, self.cfg.listen_port))
        LOG.info(
            "NLS UDP listening on %s:%d%s",
            self.cfg.listen_address,
            self.cfg.listen_port,
            f" via {self.cfg.bind_interface}" if self.cfg.bind_interface else "",
        )

    def _send_init(self, peer):
        if self._blocked(peer.id) or not self._peer_trusted(peer):
            return
        now = time.time()
        for sid, pending_item in list(self.pending.items()):
            if now - pending_item[0].created_at > self.cfg.max_clock_skew_seconds:
                self.pending.pop(sid, None)
        if any(pending_item[1].id == peer.id for pending_item in self.pending.values()):
            return
        ca_entry = self._ca_entry_for_peer(peer)
        pending = new_init(
            self.cfg.router_id,
            self.identity_public,
            self.identity,
            peer.id,
            self.local_certificate,
            self.local_ca_timestamp,
        )
        self.pending[pending.session_id] = (pending, peer)
        host, port = endpoint(peer.endpoint)
        destination = (host, port)
        if ":" in host and ipaddress.ip_address(host).is_link_local:
            if not self.cfg.bind_interface:
                raise ValueError("IPv6 link-local NLS endpoint requires a bound interface")
            destination = (host, port, 0, socket.if_nametoindex(self.cfg.bind_interface))
        self.sock.sendto(encode_message(INIT, pending.init_obj), destination)
        self.stats["handshakes"] += 1

    def _peer_for_obj(self, obj, addr):
        for peer in self.peers.values():
            if peer.public_key != obj.get("identity_public_key"):
                continue
            host, port = endpoint(peer.endpoint)
            if addr[0] == host and addr[1] == port:
                return peer
        return None

    def _peer_from_router_ca_identity(self, identity_public):
        """Resolve an initiator from the authoritative Router-CA registry.

        A destination router may receive a first handshake from an initiator
        that is not already present in its local peer cache. In that case the
        Router-CA must resolve the presented Ed25519 identity and return the
        complete binding: router id, prefix, endpoint, identity key, RSA
        encryption key, and CA metadata.
        """
        identity_public = str(identity_public or "")
        if not identity_public:
            return None

        for peer in self.peers.values():
            if peer.public_key == identity_public and self._peer_trusted(peer):
                return peer

        entry = None
        if self.ca_client:
            try:
                entry = self.ca_client.resolve_identity(identity_public)
            except Exception as exc:
                LOG.warning("Router-CA identity lookup failed: %s", exc)

        if entry is None:
            entry = next(
                (item for item in ca_store.load()
                 if item.public_key == identity_public and item.nls_ready),
                None,
            )

        if entry is None:
            return None

        peer = PeerConfig(
            entry.label,
            entry.endpoint,
            entry.public_key,
            entry.id,
            [entry.prefix],
            entry.encryption_public_key,
            entry.signing_public_key,
        )
        self.peers[peer.id] = peer
        return peer

    def _handle_init(self, packet, addr):
        try:
            kind, obj = decode_message(packet)
            if kind != INIT:
                return

            # Existing configured/CA-known peer.
            peer = self._peer_for_obj(obj, addr)
            if peer is None:
                # Unknown sender: only accept if this identity is already
                # bound to a trusted Router-CA record in the local peer set.
                peer = self._peer_from_router_ca_identity(obj.get("identity_public_key"))
                if peer is None:
                    raise ValueError(
                        "unknown NLS initiator; Router-CA identity binding is unavailable"
                    )

            if self._blocked(peer.id):
                return
            if not self._peer_trusted(peer):
                self._block(peer.id, "Router-CA trust validation failed")
                raise ValueError("Router-CA trust validation failed")

            ca_entry = self._ca_entry_for_peer(peer)
            response, send_key, recv_key = responder_key(
                obj,
                self.identity,
                self.identity_public,
                self.cfg.router_id,
                "*" if peer.router_ca_id is not None else peer.id,
                peer.public_key,
                ca_entry.certificate if ca_entry else None,
                ca_entry.timestamp if ca_entry else None,
            )
            sid = bytes.fromhex(obj["session_id"])
            now = time.time()
            for old_sid, expires in list(self.seen_handshakes.items()):
                if expires <= now:
                    self.seen_handshakes.pop(old_sid, None)
            if sid in self.seen_handshakes or sid in self.sessions:
                raise ValueError("NLS handshake replay detected")
            self.seen_handshakes[sid] = now + max(
                self.cfg.session_timeout_seconds,
                self.cfg.max_clock_skew_seconds,
            )
            self.sessions[sid] = Session(
                peer.id,
                addr,
                sid,
                send_key,
                recv_key,
                unb64(peer.public_key),
                peer.encryption_public_key,
                peer.signing_public_key,
                ReplayWindow(self.cfg.replay_window),
                time.time(),
                time.time(),
            )
            self.sock.sendto(encode_message(RESPONSE, response), addr)
            self.stats["established"] += 1
            LOG.info("NLS session established with %s", peer.id)
            self._flush_pending(peer.id)
        except Exception as exc:
            self.stats["drops"] += 1
            LOG.warning("NLS INIT rejected from %s: %s", addr, exc)

    def _handle_response(self, packet, addr):
        try:
            kind, obj = decode_message(packet)
            if kind != RESPONSE:
                return
            sid = bytes.fromhex(obj["session_id"])
            pending = self.pending.get(sid)
            if pending is None:
                return
            handshake, peer = pending
            host, port = endpoint(peer.endpoint)
            if self._blocked(peer.id):
                return
            ca_entry = self._ca_entry_for_peer(peer)
            send_key, recv_key = initiator_key(
                handshake,
                obj,
                peer.public_key,
                ca_entry.certificate if ca_entry else None,
                ca_entry.timestamp if ca_entry else None,
            )
            if addr[0] != host or addr[1] != port:
                raise ValueError("NLS response source endpoint mismatch")
            # Responses must arrive from the endpoint pinned in Router-CA.
            # Signature validation alone does not authenticate the network source.
            # (IPv4/IPv6 scope normalization is intentionally delegated to endpoint().)

            host, port = endpoint(peer.endpoint)
            if self.sock is None:
                raise ValueError("NLS socket is not initialized")
            self.sessions[sid] = Session(
                peer.id,
                (host, port),
                sid,
                send_key,
                recv_key,
                unb64(peer.public_key),
                peer.encryption_public_key,
                peer.signing_public_key,
                ReplayWindow(self.cfg.replay_window),
                time.time(),
                time.time(),
            )
            del self.pending[sid]
            self.stats["established"] += 1
            LOG.info("NLS session established with %s", peer.id)
            self._flush_pending(peer.id)
        except Exception as exc:
            self.stats["drops"] += 1
            if "pending" in locals() and pending is not None:
                self._block(pending[1].id, str(exc))
            LOG.warning("NLS response rejected: %s", exc)

    def _local_addresses(self):
        result = subprocess.run(["ip", "-j", "address", "show"], check=True, capture_output=True, text=True)
        import json
        addresses = set()
        for interface in json.loads(result.stdout):
            for info in interface.get("addr_info", []):
                address = info.get("local")
                if address:
                    addresses.add(str(ipaddress.ip_address(address)))
        return addresses

    def _local_lan_networks(self):
        """Return prefixes directly served by interfaces configured as NLS LAN."""
        router_data = __import__("nlsxnetos.router_config", fromlist=["load"]).load()["router"]
        networks = []
        for name, item in router_data.get("interfaces", {}).items():
            if item.get("nls_role") != "lan" or not item.get("enabled", True):
                continue
            for value in item.get("addresses", []):
                try:
                    networks.append(ipaddress.ip_interface(value).network)
                except ValueError:
                    LOG.warning("Ignoring invalid LAN address %s on %s", value, name)
        return networks

    def _is_local_destination(self, destination):
        address = ipaddress.ip_address(destination)
        if address in {ipaddress.ip_address(x) for x in self._local_addresses()}:
            return True
        return any(address.version == network.version and address in network for network in self._local_lan_networks())

    def _known_peer_for_endpoint(self, addr):
        for peer in self.peers.values():
            try:
                host, port = endpoint(peer.endpoint)
            except ValueError:
                continue
            if addr[0] == host and addr[1] == port:
                return peer
        return None

    def _next_nls_endpoint(self, destination, incoming_addr=None):
        destination = str(ipaddress.ip_address(destination))
        now = time.time()
        cached = self.forward_cache.get(destination)
        if cached and cached[0] > now:
            return cached[1]

        peer = self._peer_for_destination(destination)
        if peer is None:
            return None

        final_host, final_port = endpoint(peer.endpoint)
        route = lookup_route(final_host) or wait_for_route(final_host, timeout=5.0)
        if route is None:
            return None

        next_host = route.get("via")
        next_peer = self._refresh_ca_next_hop(next_host) if next_host else None
        if next_peer is not None:
            next_endpoint = endpoint(next_peer.endpoint)
            if incoming_addr and next_endpoint == incoming_addr[:2]:
                raise RuntimeError("OSPF/FIB selected the incoming NLS hop; forwarding loop prevented")
            result = (next_peer.id, next_endpoint)
        else:
            if next_host:
                raise RuntimeError(f"OSPF next-hop {next_host} is not registered as an NLS router")
            if incoming_addr and (final_host, final_port) == incoming_addr[:2]:
                raise RuntimeError("destination endpoint equals incoming NLS hop")
            result = (peer.id, (final_host, final_port))

        self.forward_cache[destination] = (now + 10, result)
        return result

    def _forward_data(self, packet, addr, metadata):
        route = self._next_nls_endpoint(metadata["destination_ip"], incoming_addr=addr)
        if route is None:
            raise ValueError(f"no NLS path to destination {metadata['destination_ip']}")
        peer_id, target = route
        host, port = target
        destination_addr = target
        if ":" in host and ipaddress.ip_address(host).is_link_local:
            if not self.cfg.bind_interface:
                raise ValueError("IPv6 link-local next NLS hop requires a bound interface")
            destination_addr = (host, port, 0, socket.if_nametoindex(self.cfg.bind_interface))
        self.sock.sendto(packet, destination_addr)
        self.stats["tx"] += 1
        LOG.debug("NLS forwarding protected packet for %s via %s", metadata["destination_ip"], peer_id)
        return True

    @staticmethod
    def _packet_sequence(packet):
        if len(packet) < HEADER.size:
            raise ValueError("NLS encapsulated packet is too short")
        return HEADER.unpack(packet[:HEADER.size])[7]

    @staticmethod
    def _packet_destination(packet):
        if len(packet) < 1:
            raise ValueError("empty IP packet")
        version = packet[0] >> 4
        if version == 4:
            if len(packet) < 20:
                raise ValueError("IPv4 packet is too short")
            return str(ipaddress.IPv4Address(packet[16:20]))
        if version == 6:
            if len(packet) < 40:
                raise ValueError("IPv6 packet is too short")
            return str(ipaddress.IPv6Address(packet[24:40]))
        raise ValueError("unsupported IP packet version")

    def _refresh_ca_peer(self, destination):
        entry = None
        if self.ca_client:
            try:
                entry = self.ca_client.resolve(destination)
            except Exception as exc:
                LOG.warning("Router-CA destination lookup for %s failed: %s", destination, exc)
        if entry is None:
            entry = ca_store.lookup(destination)
        if entry is None:
            return None
        peer = PeerConfig(
            entry.label,
            entry.endpoint,
            entry.public_key,
            entry.id,
            [entry.prefix],
            entry.encryption_public_key,
        )
        self.peers[peer.id] = peer
        return peer

    def _refresh_ca_next_hop(self, address):
        entry = None
        if self.ca_client:
            try:
                entry = self.ca_client.resolve_next_hop(address)
            except Exception as exc:
                LOG.warning("Router-CA next-hop lookup for %s failed: %s", address, exc)
        if entry is None:
            entry = ca_store.lookup_endpoint(address)
        if entry is None:
            return None
        peer = PeerConfig(
            f"router-ca-{entry.id}",
            entry.endpoint,
            entry.public_key,
            entry.id,
            [entry.prefix],
            entry.encryption_public_key,
        )
        self.peers[peer.id] = peer
        return peer

    def _handle_data(self, packet, addr):
        try:
            metadata = peek_ip_packet(packet)
            if not self._is_local_destination(metadata["destination_ip"]):
                return self._forward_data(packet, addr, metadata)

            sid = metadata["session_id"]
            session = self.sessions.get(sid)
            if session is None:
                raise ValueError("unknown NLS session")
            if (session.endpoint[0] != addr[0] or session.endpoint[1] != addr[1]) and self._known_peer_for_endpoint(addr) is None:
                raise ValueError("NLS packet arrived from an unknown forwarding router")

            sequence = metadata["sequence"]
            if not session.recv_replay.can_accept(sequence):
                raise ValueError("NLS replay detected")
            result = open_ip_packet(
                self.encryption_private_key,
                packet,
                session.session_id,
                session.peer_identity,
                session.peer_signing_public_key,
                self.cfg.max_clock_skew_seconds,
            )
            if not session.recv_replay.mark(sequence):
                raise ValueError("NLS replay detected")
            if self.tun is None:
                raise ValueError("NLS data plane requires the TUN interface")
            self.tun.write(result["payload"])
            self.stats["rx"] += 1
            session.last_seen = time.time()
        except Exception as exc:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            LOG.warning("NLS DATA dropped from %s: %s", addr, exc)

    def _peer_for_destination(self, destination):
        peer = self._refresh_ca_peer(destination) if self.cfg.auto_router_ca else None
        if peer is not None:
            return peer
        address = ipaddress.ip_address(destination)
        candidates = []
        for peer in self.peers.values():
            for prefix in peer.allowed_prefixes:
                network = ipaddress.ip_network(prefix, strict=False)
                if network.version == address.version and address in network:
                    candidates.append((network.prefixlen, peer))
        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]

    def _session_for_destination(self, destination):
        peer = self._peer_for_destination(destination)
        if peer is None:
            return None
        if not peer.encryption_public_key:
            return None
        sessions = [s for s in self.sessions.values() if s.peer_id == peer.id]
        return max(sessions, key=lambda s: s.last_seen) if sessions else None

    def _queue_for_handshake(self, peer, payload):
        queue = self.pending_payloads.setdefault(peer.id, [])
        if len(queue) >= self.max_pending_payloads:
            queue.pop(0)
            self.stats["drops"] += 1
        queue.append(payload)
        self._send_init(peer)

    def _flush_pending(self, peer_id):
        queue = self.pending_payloads.pop(peer_id, [])
        for payload in queue:
            try:
                self._send_payload(payload)
            except Exception as exc:
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                LOG.warning("queued NLS DATA send failed for %s: %s", peer_id, exc)

    def _send_payload(self, payload):
        destination = self._packet_destination(payload)
        session = self._session_for_destination(destination)
        if session is None:
            peer = self._peer_for_destination(destination)
            if peer is None:
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                LOG.warning("NLS DATA has no Router-CA destination for %s", destination)
                return False
            if not self._peer_trusted(peer):
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                LOG.warning("NLS DATA blocked: Router-CA trust failed for %s", peer.id)
                return False
            if not peer.encryption_public_key:
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                LOG.warning("NLS DATA blocked: destination RSA public key missing for %s", peer.id)
                return False
            self._queue_for_handshake(peer, payload)
            return False
        if not session.peer_id:
            raise ValueError("NLS session has no destination peer")
        peer = self.peers.get(session.peer_id)
        if peer is None or not peer.encryption_public_key:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            LOG.warning("NLS DATA blocked: destination RSA public key is missing for %s", session.peer_id)
            return False
        packet = seal_ip_packet(
            peer.encryption_public_key,
            self.encryption_private_key,
            self.signing_private_key,
            session.session_id,
            session.tx_sequence,
            destination,
            self.identity_raw,
            payload,
        )
        session.tx_sequence += 1
        self.sock.sendto(packet, session.endpoint)
        session.last_tx = time.time()
        self.stats["tx"] += 1
        return True

    def _shutdown(self, *_args):
        self.running = False

    def run(self):
        if not self.cfg.enabled:
            LOG.warning("NLS is disabled in configuration; exiting")
            return
        if not self.ca_client and not ca_store.active_entries():
            LOG.warning("NLS is inactive: configure an external Router-CA server or local trust cache")
            return
        if not self.cfg.tun.enabled:
            LOG.warning("NLS is inactive: TUN is disabled")
            return
        if not self.cfg.bind_interface and self.cfg.listen_address in ("", "0.0.0.0", "::"):
            raise RuntimeError("NLS requires an explicit WAN bind interface or non-wildcard listen address")
        self._validate_tun_mtu()
        if self.ca_client:
            self.ca_client.health()
            if not self.cfg.advertised_endpoint:
                LOG.warning("Router-CA registration skipped: advertised_endpoint is not configured")
            else:
                try:
                    from .rsa import public_key_b64 as rsa_public_key_b64
                    registration = self.ca_client.register(
                        router_id=self.cfg.router_id,
                        endpoint=self.cfg.advertised_endpoint,
                        public_key=self.identity_public,
                        encryption_public_key=rsa_public_key_b64(self.encryption_private_key),
                        signing_public_key=rsa_signing_public_key_b64(self.signing_private_key),
                    )
                    record = registration.get("router", registration)
                    self.local_certificate = record.get("certificate")
                    self.local_ca_timestamp = record.get("timestamp")
                    LOG.info("Router registered with external Router-CA")
                except Exception as exc:
                    LOG.error("Router-CA registration failed: %s", exc)
                    raise
        self._bind()
        self.tun = TunDevice(self.cfg.tun.name).open()
        try:
            subprocess.run(
                ["ip", "link", "set", "dev", self.tun.name, "mtu", str(self.cfg.tun.mtu)],
                check=True,
            )
            subprocess.run(
                ["ip", "link", "set", "dev", self.tun.name, "up"],
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            self.tun.close()
            self.tun = None
            raise RuntimeError("unable to configure NLS TUN interface") from exc
        install_tun_routes(list(self.peers.values()), self.tun.name)
        router_data = __import__("nlsxnetos.router_config", fromlist=["load"]).load()["router"]
        lan_interfaces = [name for name, item in router_data.get("interfaces", {}).items() if item.get("nls_role") == "lan"]
        install_lan_policy(lan_interfaces, self.tun.name)
        LOG.info("NLS TUN device ready: %s", self.tun.name)
        while self.running:
            now = time.time()
            for sid, session in list(self.sessions.items()):
                if now - session.last_seen > self.cfg.session_timeout_seconds:
                    del self.sessions[sid]
            for sid, expires in list(self.seen_handshakes.items()):
                if expires <= now:
                    del self.seen_handshakes[sid]
            ready, _, _ = select.select([self.sock, self.tun], [], [], 1.0)
            for item in ready:
                if item is self.sock:
                    packet, addr = self.sock.recvfrom(MAX_DATAGRAM)
                    if packet.startswith(b"NLSH"):
                        kind, _ = decode_message(packet)
                        if kind == INIT:
                            self._handle_init(packet, addr)
                        elif kind == RESPONSE:
                            self._handle_response(packet, addr)
                    elif packet.startswith(b"NLE1"):
                        self._handle_data(packet, addr)
                else:
                    try:
                        payload = self.tun.read()
                    except BlockingIOError:
                        continue
                    if payload:
                        self._send_payload(payload)
        remove_tun_routes()
        router_data = __import__("nlsxnetos.router_config", fromlist=["load"]).load()["router"]
        lan_interfaces = [name for name, item in router_data.get("interfaces", {}).items() if item.get("nls_role") == "lan"]
        remove_lan_policy(lan_interfaces, self.cfg.tun.name)
        if self.tun:
            self.tun.close()
        if self.sock:
            self.sock.close()


def run():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    daemon = NLSDaemon(load())
    signal.signal(signal.SIGTERM, daemon._shutdown)
    signal.signal(signal.SIGINT, daemon._shutdown)
    daemon.run()
