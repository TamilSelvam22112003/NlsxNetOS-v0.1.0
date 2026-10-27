import ipaddress
import logging
import select
import signal
import socket
import subprocess
import time
import secrets
from dataclasses import dataclass

from security.trust.router_ca import store as ca_store
from .config import PeerConfig, endpoint, load
from .encapsulation import HEADER, open_ip_packet, seal_ip_packet
from .endpoint_envelope import HEADER as ENDPOINT_HEADER, EndpointEnvelopeError, open_endpoint_packet, seal_endpoint_packet, verify_endpoint_envelope
from .relay_envelope import open_relay_layer, seal_relay_layer
from .relay_forwarding import HopContext, RelayForwardingError, prepare_forward
from .transparent import create_transparent_socket, recv_transparent, send_transparent, install_tproxy, remove_tproxy, install_forward_routes, remove_forward_routes
from .handshake import INIT, RESPONSE, decode_message, encode_message, initiator_key, new_init, responder_key
from .identity import load_or_create, public_key_b64, unb64, decode_public_key
from . import lsdb
from .replay import ReplayWindow
from .rsa import load_or_create as load_rsa_private_key
from .routing import install_tun_routes, remove_tun_routes
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
    recv_replay: ReplayWindow
    last_seen: float
    last_tx: float
    tx_sequence: int = 0
    vip: str = ""


class NLSDaemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.identity = load_or_create(cfg.identity_key)
        self.identity_public = public_key_b64(self.identity)
        self.identity_raw = unb64(self.identity_public)
        self.encryption_private_key = load_rsa_private_key(cfg.encryption_private_key)
        self.sock = None
        self.tun = None
        self.peers = {p.id: p for p in cfg.peers}
        self.sessions = {}
        self.pending = {}
        self.seen_handshakes = {}
        self.blocked = {}
        self.pending_payloads = {}
        self.endpoint_tx = {}
        self.endpoint_rx = {}
        self.tproxy_active = False
        self.forward_routes_active = False
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

    def _peer_trusted(self, peer):
        if self._blocked(peer.id):
            return False
        if peer.router_ca_id is None:
            return True
        entry = next((e for e in ca_store.load() if e.id == peer.router_ca_id), None)
        ok = bool(
            entry
            and entry.public_key
            and entry.public_key == peer.public_key
            and (not entry.endpoint or entry.endpoint == peer.endpoint)
        )
        if not ok:
            LOG.warning("peer %s rejected: Router-CA identity/endpoint mismatch", peer.id)
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
        if self.cfg.forwarding_mode == "destination_preserving":
            import json
            addresses = subprocess.run(
                ["ip", "-j", "addr", "show", "dev", self.cfg.bind_interface],
                check=True, capture_output=True, text=True,
            )
            configured = ipaddress.ip_address(self.cfg.listen_address)
            assigned = {
                ipaddress.ip_address(info["local"])
                for iface in json.loads(addresses.stdout)
                for info in iface.get("addr_info", [])
                if info.get("scope") == "global"
            }
            if configured not in assigned:
                raise RuntimeError("listen_address must be assigned to bind_interface as a global WAN address")
        # Legacy NLE1 requires a conservative non-fragmented payload MTU.
        # NLE2+NLR1 may exceed the WAN MTU; IPv6 source fragmentation is enabled
        # on the transparent socket and must be verified in the WAN lab.
        if self.cfg.forwarding_mode == "destination_preserving":
            if self.cfg.tun.mtu < 1280:
                raise RuntimeError("destination-preserving IPv6 mode requires TUN MTU >= 1280")
            safe_mtu = mtu
        else:
            overhead = 40 + 8 + HEADER.size + 384 + 16
            safe_mtu = mtu - overhead
        if self.cfg.tun.mtu > safe_mtu:
            raise RuntimeError(
                f"NLS TUN MTU {self.cfg.tun.mtu} exceeds safe transport MTU {safe_mtu} "
                f"for {self.cfg.bind_interface} (WAN MTU {mtu})"
            )

    def _send_control_datagram(self, packet, destination):
        """Send handshake/control traffic outside the marked data-plane route table."""
        if self.cfg.forwarding_mode == "destination_preserving" and self.sock is not None:
            mark_option = getattr(socket, "SO_MARK", 36)
            self.sock.setsockopt(socket.SOL_SOCKET, mark_option, 0)
            try:
                return self.sock.sendto(packet, destination)
            finally:
                self.sock.setsockopt(socket.SOL_SOCKET, mark_option, 0x5)
        return self.sock.sendto(packet, destination)

    def _bind(self):
        if self.cfg.forwarding_mode == "destination_preserving":
            self.sock = create_transparent_socket("::", self.cfg.listen_port)
            self.sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x5)
            LOG.info("NLS transparent UDP listener active on [::]:%d via %s",
                     self.cfg.listen_port, self.cfg.bind_interface)
            return
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

    def _original_router_ip(self):
        if self.cfg.listen_address not in ("", "0.0.0.0", "::"):
            return self.cfg.listen_address
        if self.cfg.bind_interface:
            result = subprocess.run(
                ["ip", "-j", "addr", "show", "dev", self.cfg.bind_interface],
                check=True,
                capture_output=True,
                text=True,
            )
            import json
            addresses = json.loads(result.stdout)
            for iface in addresses:
                for addr in iface.get("addr_info", []):
                    if addr.get("family") == "inet6" and addr.get("scope") == "global":
                        return addr["local"]
                for addr in iface.get("addr_info", []):
                    if addr.get("family") == "inet" and addr.get("scope") == "global":
                        return addr["local"]
        raise RuntimeError("unable to determine source router original IP")
    
    def _send_init(self, peer, original_ip):
        if self._blocked(peer.id) or not self._peer_trusted(peer):
            return
        now = time.time()
        for sid, pending_item in list(self.pending.items()):
            if now - pending_item[0].created_at > self.cfg.max_clock_skew_seconds:
                self.pending.pop(sid, None)
        if any(pending_item[1].id == peer.id for pending_item in self.pending.values()):
            return
        # The INIT certificate identifies the *initiating router* in the
        # Router-CA registry.  The peer entry is the destination identity,
        # so using peer.router_ca_id here would bind the source router to the
        # destination's registry record and causes the responder to reject it.
        local_ca_entry = next(
            (
                e for e in ca_store.active_entries()
                if e.public_key == self.identity_public
            ),
            None,
        )
        if local_ca_entry is None:
            raise ValueError(
                "local Router-CA identity is not registered for NLS"
            )

        local_endpoint_host = original_ip
        local_endpoint = (
            f"[{local_endpoint_host}]:{self.cfg.listen_port}"
            if ":" in local_endpoint_host
            else f"{local_endpoint_host}:{self.cfg.listen_port}"
        )
        if local_ca_entry.endpoint != local_endpoint:
            raise ValueError(
                "local Router-CA endpoint does not match NLS listen endpoint"
            )

        pending = new_init(
            self.cfg.router_id,
            self.identity_public,
            self.identity,
            peer.id,
            original_ip,
            local_ca_entry.id,
            local_ca_entry.public_key,
            local_endpoint,
        )
        self.pending[pending.session_id] = (pending, peer)
        host, port = endpoint(peer.endpoint)
        destination = (host, port)
        if ":" in host and ipaddress.ip_address(host).is_link_local:
            if not self.cfg.bind_interface:
                raise ValueError("IPv6 link-local NLS endpoint requires a bound interface")
            destination = (host, port, 0, socket.if_nametoindex(self.cfg.bind_interface))
        self._send_control_datagram(encode_message(INIT, pending.init_obj), destination)
        self.stats["handshakes"] += 1

    def _peer_for_obj(self, obj, addr):
        for peer in self.peers.values():
            if peer.public_key != obj.get("identity_public_key"):
                continue
            host, port = endpoint(peer.endpoint)
            if addr[0] == host and addr[1] == port:
                return peer

        # CA-authorized discovery: an otherwise unknown router may be
        # admitted only when its signed certificate claim matches a local
        # authoritative Router-CA entry and the network source endpoint.
        certificate = obj.get("certificate") or {}
        ca_id = certificate.get("router_ca_id")
        if ca_id is None:
            return None
        entry = next((e for e in ca_store.active_entries() if e.id == ca_id), None)
        if entry is None or entry.public_key != obj.get("identity_public_key"):
            return None
        if certificate.get("endpoint") != entry.endpoint:
            return None
        host, port = endpoint(entry.endpoint)
        if addr[0] != host or addr[1] != port:
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

    def _handle_init(self, packet, addr, destination=None, interface_index=None):
        try:
            kind, obj = decode_message(packet)
            if kind != INIT:
                return
            if self.cfg.forwarding_mode == "destination_preserving":
                expected_ip = ipaddress.ip_address(self.cfg.listen_address)
                if destination is None or ipaddress.ip_address(destination) != expected_ip:
                    raise ValueError("handshake arrived at an unexpected local destination")
                if interface_index is None or interface_index <= 0:
                    raise ValueError("handshake is missing kernel-verified ingress interface")
                if not (len(addr) >= 2 and int(addr[1]) == self.cfg.listen_port):
                    raise ValueError("handshake source UDP port does not match the configured NLS port")
            peer = self._peer_for_obj(obj, addr)
            if peer is None:
                raise ValueError("unknown or untrusted peer")
            if self._blocked(peer.id):
                return
            if not self._peer_trusted(peer):
                self._block(peer.id, "Router-CA trust validation failed")
                raise ValueError("untrusted peer")
            response, send_key, recv_key = responder_key(
                obj,
                self.identity,
                self.identity_public,
                self.cfg.router_id,
                "*" if peer.router_ca_id is not None else peer.id,
                peer.public_key,
                peer.router_ca_id,
                peer.endpoint,
            )
            sid = bytes.fromhex(obj["session_id"])
            now = time.time()
            for old_sid, expires in list(self.seen_handshakes.items()):
                if expires <= now:
                    self.seen_handshakes.pop(old_sid, None)
            if sid in self.seen_handshakes or sid in self.sessions:
                raise ValueError("NLS handshake replay detected")
            self.seen_handshakes[sid] = now + max(self.cfg.session_timeout_seconds, self.cfg.max_clock_skew_seconds)
            self.sessions[sid] = Session(
                peer.id,
                addr,
                sid,
                send_key,
                recv_key,
                unb64(peer.public_key),
                ReplayWindow(self.cfg.replay_window),
                time.time(),
                time.time(),
            )
            lsdb.upsert(
                obj["vip"],
                peer.id,
                obj["original_ip"],
                peer.public_key,
                time.time() + self.cfg.session_timeout_seconds,
            )
            self._send_control_datagram(encode_message(RESPONSE, response), addr)
            self.stats["established"] += 1
            LOG.info("NLS session established with %s", peer.id)
            self._flush_pending(peer.id)
        except Exception as exc:
            self.stats["drops"] += 1
            peer = self._peer_for_obj(locals().get("obj", {}), addr) if "obj" in locals() else None
            if peer is not None:
                self._block(peer.id, str(exc))
            LOG.warning("NLS INIT rejected from %s: %s", addr, exc)

    def _handle_response(self, packet, addr, destination=None, interface_index=None):
        try:
            kind, obj = decode_message(packet)
            if kind != RESPONSE:
                return
            if self.cfg.forwarding_mode == "destination_preserving":
                expected_ip = ipaddress.ip_address(self.cfg.listen_address)
                if destination is None or ipaddress.ip_address(destination) != expected_ip:
                    raise ValueError("handshake response arrived at an unexpected local destination")
                if interface_index is None or interface_index <= 0:
                    raise ValueError("handshake response is missing kernel-verified ingress interface")
                if not (len(addr) >= 2 and int(addr[1]) == self.cfg.listen_port):
                    raise ValueError("handshake response source UDP port does not match the configured NLS port")
            sid = bytes.fromhex(obj["session_id"])
            pending = self.pending.get(sid)
            if pending is None:
                return
            handshake, peer = pending
            host, port = endpoint(peer.endpoint)
            if self._blocked(peer.id):
                return
            send_key, recv_key = initiator_key(handshake, obj, peer.public_key)
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
                ReplayWindow(self.cfg.replay_window),
                time.time(),
                time.time(),
            )
            lsdb.upsert(
                obj["vip"],
                peer.id,
                obj["original_ip"],
                peer.public_key,
                time.time() + self.cfg.session_timeout_seconds,
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
        entry = ca_store.lookup(destination)
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
            if len(packet) < HEADER.size + 16:
                raise ValueError("NLS DATA packet too short")
            sid = HEADER.unpack(packet[:HEADER.size])[4]
            session = self.sessions.get(sid)
            if session is None or session.endpoint[0] != addr[0] or session.endpoint[1] != addr[1]:
                raise ValueError("unknown NLS session")
            sequence = self._packet_sequence(packet)
            if not session.recv_replay.can_accept(sequence):
                raise ValueError("NLS replay detected")
            result = open_ip_packet(
                self.encryption_private_key,
                packet,
                session.session_id,
                session.peer_identity,
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
        self._send_init(peer, self._original_router_ip())

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
        if self.cfg.forwarding_mode == "destination_preserving":
            try:
                return self._send_payload_destination_preserving(payload)
            except Exception as exc:
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                LOG.warning("NLS destination-preserving send failed: %s", exc)
                return False
        destination = self._packet_destination(payload)
        # IPv6 link-local multicast (for example ff02::1/ff02::2) is scoped to a LAN.
        # It must remain on the local interface and cannot be routed through a unicast NLS peer.
        # Drop only multicast from the NLS TUN path; ordinary LAN IPv6 ND/RA stays on the LAN.
        address = ipaddress.ip_address(destination)
        if address.version == 6 and address.is_multicast:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            LOG.debug("NLS multicast packet kept off tunnel: %s", destination)
            return False
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

    def _send_payload_destination_preserving(self, payload):
        destination = self._packet_destination(payload)
        address = ipaddress.ip_address(destination)
        if address.version != 6 or address.is_multicast or address.is_unspecified:
            raise ValueError("destination-preserving runtime currently requires unicast IPv6 packets")
        destination_entry = ca_store.lookup(destination)
        if destination_entry is None or not destination_entry.encryption_public_key:
            raise ValueError("destination is not registered with Router-CA for NLE2 encryption")
        session = self._session_for_destination(destination)
        if session is None:
            peer = self._peer_for_destination(destination)
            if peer is None or not self._peer_trusted(peer):
                raise ValueError("no authenticated configured next-hop route for destination")
            self._queue_for_handshake(peer, payload)
            return False
        peer = self.peers.get(session.peer_id)
        if peer is None:
            raise ValueError("next-hop session has no configured peer")
        next_hop, next_port = endpoint(peer.endpoint)
        if ipaddress.ip_address(next_hop).version != 6 or ipaddress.ip_address(next_hop).is_link_local:
            raise ValueError("destination-preserving mode requires a global IPv6 next-hop")
        local_locator = self._original_router_ip()
        if ipaddress.ip_address(local_locator).version != 6:
            raise ValueError("destination-preserving mode requires an IPv6 WAN locator")

        endpoint_sid, endpoint_sequence = self.endpoint_tx.get(
            destination_entry.id, (secrets.token_bytes(16), 0)
        )
        endpoint_packet = seal_endpoint_packet(
            destination_entry.encryption_public_key,
            self.identity,
            endpoint_sid,
            endpoint_sequence,
            destination,
            payload,
        )
        relay_packet = seal_relay_layer(
            session.send_key,
            session.session_id,
            session.tx_sequence,
            next_hop,
            next_port,
            endpoint_packet,
            previous_hop_source_locator=local_locator,
        )
        send_transparent(
            self.sock, relay_packet, destination, self.cfg.listen_port,
            local_locator, interface_index=socket.if_nametoindex(self.cfg.bind_interface),
        )
        self.endpoint_tx[destination_entry.id] = (endpoint_sid, endpoint_sequence + 1)
        session.tx_sequence += 1
        session.last_tx = time.time()
        self.stats["tx"] += 1
        return True

    def _outgoing_interface_index(self, destination):
        result = subprocess.run(
            ["ip", "-6", "route", "get", destination, "mark", "0x5"],
            check=True, capture_output=True, text=True,
        )
        fields = result.stdout.splitlines()[0].split()
        if "dev" not in fields:
            raise RuntimeError("cannot determine egress interface for final destination")
        return socket.if_nametoindex(fields[fields.index("dev") + 1])

    def _is_local_destination(self, destination):
        """Return true for this router or a registered endpoint directly on its LAN."""
        address = ipaddress.ip_address(destination)
        for entry in ca_store.active_entries():
            if entry.public_key != self.identity_public:
                continue
            try:
                network = ipaddress.ip_network(entry.prefix, strict=False)
            except ValueError:
                continue
            if network.version == address.version and address in network:
                return True
        if address.version != 6 or ca_store.lookup(str(address)) is None:
            return False
        try:
            result = subprocess.run(
                ["ip", "-6", "route", "get", str(address)],
                check=True, capture_output=True, text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return False
        fields = result.stdout.split()
        if "dev" not in fields or "via" in fields:
            return False
        try:
            egress = fields[fields.index("dev") + 1]
        except IndexError:
            return False
        return bool(egress and egress != self.cfg.bind_interface)

    def _ingress_is_expected(self, session, interface_index):
        """Require relay packets to arrive on the configured WAN interface."""
        if not self.cfg.bind_interface or not isinstance(interface_index, int) or interface_index <= 0:
            return False
        try:
            expected_ifindex = socket.if_nametoindex(self.cfg.bind_interface)
            peer = self.peers.get(session.peer_id)
            if peer is None:
                return False
            peer_host, _peer_port = endpoint(peer.endpoint)
            peer_address = ipaddress.ip_address(peer_host)
        except (KeyError, OSError, ValueError):
            return False
        return interface_index == expected_ifindex and peer_address.version == 6

    def _ingress_is_expected_endpoint_source(self, source_address, interface_index):
        """Permit endpoint-agent traffic only when it arrives on a non-WAN interface."""
        if not self.cfg.bind_interface or not isinstance(interface_index, int) or interface_index <= 0:
            return False
        try:
            wan_index = socket.if_nametoindex(self.cfg.bind_interface)
            source = ipaddress.ip_address(source_address)
            route = subprocess.run(
                ["ip", "-6", "route", "get", str(source)],
                check=True, capture_output=True, text=True,
            )
            fields = route.stdout.split()
            if "dev" not in fields or "via" in fields:
                return False
            source_ifname = fields[fields.index("dev") + 1]
            source_ifindex = socket.if_nametoindex(source_ifname)
            if source_ifindex != interface_index or interface_index == wan_index:
                return False
            entry = ca_store.lookup(str(source))
            if entry is None:
                return False
            network = ipaddress.ip_network(entry.prefix, strict=False)
        except (OSError, subprocess.CalledProcessError, ValueError, IndexError):
            return False
        return source.version == network.version and source in network

    def _handle_relay_data(self, packet, addr, destination):
        try:
            inbound = next(
                (item for item in self.sessions.values()
                 if item.endpoint[0] == addr[0] and item.endpoint[1] == addr[1]),
                None,
            )
            if inbound is None:
                raise RelayForwardingError("no authenticated inbound hop session for outer source")
            if not (len(addr) >= 2 and int(addr[1]) == self.cfg.listen_port):
                raise RelayForwardingError("relay packet source UDP port does not match the configured NLS port")
            if not self._ingress_is_expected(inbound, getattr(self, "_last_received_interface_index", 0)):
                raise RelayForwardingError("relay packet arrived on an unauthorized ingress interface")
            local_locator = self._original_router_ip()

            if self._is_local_destination(destination):
                layer = open_relay_layer(
                    inbound.recv_key, packet, expected_hop_token=inbound.session_id
                )
                if not inbound.recv_replay.can_accept(layer.sequence):
                    raise RelayForwardingError("NLS relay replay detected")
                if layer.previous_hop_source_locator != str(ipaddress.ip_address(addr[0])):
                    raise RelayForwardingError("encrypted previous-hop locator does not match observed source")
                if (layer.next_hop_address != str(ipaddress.ip_address(local_locator))
                        or layer.next_hop_port != self.cfg.listen_port):
                    raise RelayForwardingError("NLR1 envelope is not addressed to this destination router")
                if not inbound.recv_replay.mark(layer.sequence):
                    raise RelayForwardingError("NLS relay replay detected")
                if len(layer.inner_envelope) < ENDPOINT_HEADER.size:
                    raise EndpointEnvelopeError("NLE2 endpoint envelope is truncated")
                fields = ENDPOINT_HEADER.unpack_from(layer.inner_envelope)
                magic, version, endpoint_sid, origin_identity = fields[:4]
                if magic != b"NLE2" or version != 1:
                    raise EndpointEnvelopeError("unsupported endpoint envelope")
                origin_entry = next(
                    (entry for entry in ca_store.active_entries()
                     if unb64(entry.public_key) == origin_identity),
                    None,
                )
                if origin_entry is None:
                    raise EndpointEnvelopeError("NLE2 origin identity is not active in Router-CA")
                metadata = verify_endpoint_envelope(
                    decode_public_key(origin_entry.public_key),
                    layer.inner_envelope,
                    max_clock_skew=self.cfg.max_clock_skew_seconds,
                )
                replay_key = (origin_identity, endpoint_sid)
                if replay_key not in self.endpoint_rx and len(self.endpoint_rx) >= 4096:
                    raise EndpointEnvelopeError("NLE2 replay-session capacity reached")
                replay = self.endpoint_rx.setdefault(
                    replay_key, ReplayWindow(self.cfg.replay_window)
                )
                if not replay.can_accept(metadata["sequence"]):
                    raise EndpointEnvelopeError("NLE2 endpoint replay detected")
                if not replay.mark(metadata["sequence"]):
                    raise EndpointEnvelopeError("NLE2 endpoint replay detected")
                endpoint_entry = ca_store.lookup(destination)
                if endpoint_entry is None:
                    raise EndpointEnvelopeError("destination has no active Router-CA endpoint entry")
                if endpoint_entry.public_key == self.identity_public:
                    # For router-addressed destinations, this router owns the
                    # endpoint key and may decrypt before delivering to its LAN.
                    opened = open_endpoint_packet(
                        self.encryption_private_key,
                        decode_public_key(origin_entry.public_key),
                        layer.inner_envelope,
                        expected_destination=destination,
                        expected_session_id=endpoint_sid,
                        max_clock_skew=self.cfg.max_clock_skew_seconds,
                    )
                    if self.tun is None:
                        raise RuntimeError("NLS data plane requires the TUN interface")
                    self.tun.write(opened["payload"])
                else:
                    # Server/host endpoint entries own the end-to-end key.
                    # This router forwards the NLE2 envelope without decrypting it.
                    send_transparent(
                        self.sock, layer.inner_envelope, destination,
                        self.cfg.listen_port, local_locator,
                        interface_index=self._outgoing_interface_index(destination),
                    )
                self.stats["rx"] += 1
                self.stats["tx"] += 1
                inbound.last_seen = time.time()
                return

            outbound = self._session_for_destination(destination)
            if outbound is None:
                next_peer = self._peer_for_destination(destination)
                if next_peer is not None and self._peer_trusted(next_peer):
                    self._send_init(next_peer, local_locator)
                raise RelayForwardingError("authorized next-hop session unavailable; packet dropped fail-closed")
            next_peer = self.peers.get(outbound.peer_id)
            if next_peer is None:
                raise RelayForwardingError("next-hop peer configuration missing")
            next_host, next_port = endpoint(next_peer.endpoint)
            plan = prepare_forward(
                packet,
                observed_outer_source=addr[0],
                outer_destination=destination,
                outer_destination_port=self.cfg.listen_port,
                local_wan_locator=local_locator,
                listen_port=self.cfg.listen_port,
                inbound=HopContext(inbound.recv_key, inbound.session_id,
                                   inbound.tx_sequence, inbound.recv_replay),
                outbound=HopContext(outbound.send_key, outbound.session_id,
                                    outbound.tx_sequence, ReplayWindow(self.cfg.replay_window)),
                configured_next_hop=next_host,
                configured_next_hop_port=next_port,
            )
            send_transparent(
                self.sock, plan.packet, plan.outer_destination,
                plan.outer_destination_port, local_locator,
                interface_index=socket.if_nametoindex(self.cfg.bind_interface),
            )
            outbound.tx_sequence += 1
            outbound.last_tx = time.time()
            inbound.last_seen = time.time()
            self.stats["rx"] += 1
            self.stats["tx"] += 1
        except Exception as exc:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            LOG.warning("NLS destination-preserving packet dropped from %s: %s", addr, exc)

    def _handle_local_endpoint_packet(self, packet, addr, destination):
        """Wrap a signed endpoint-agent packet in the first router hop layer."""
        try:
            if not (len(addr) >= 2 and int(addr[1]) == self.cfg.listen_port):
                raise RelayForwardingError("endpoint-agent source UDP port does not match the configured NLS port")
            if destination is None:
                raise RelayForwardingError("endpoint-agent packet is missing its kernel-observed final destination")
            final_destination = ipaddress.ip_address(destination)
            if final_destination.version != 6 or final_destination.is_unspecified or final_destination.is_multicast:
                raise RelayForwardingError("endpoint-agent packet final destination must be unicast IPv6")
            ingress_ifindex = getattr(self, "_last_received_interface_index", 0)
            if not self._ingress_is_expected_endpoint_source(addr[0], ingress_ifindex):
                raise RelayForwardingError("endpoint-agent packet arrived on an unauthorized LAN interface")
            try:
                source_endpoint = ca_store.lookup(str(ipaddress.ip_address(addr[0])))
                if source_endpoint is None:
                    raise RelayForwardingError("endpoint-agent source is absent from active Router-CA")
                if str(source_endpoint.public_key) == self.identity_public:
                    raise RelayForwardingError("router must not accept its own NLE2 envelope as server-originated traffic")
            except ValueError as exc:
                raise RelayForwardingError("invalid endpoint-agent source address") from exc
            if len(packet) < ENDPOINT_HEADER.size:
                raise EndpointEnvelopeError("NLE2 endpoint envelope is truncated")
            fields = ENDPOINT_HEADER.unpack_from(packet)
            magic, version, endpoint_sid, origin_identity, endpoint_sequence = fields[:5]
            if magic != b"NLE2" or version != 1:
                raise EndpointEnvelopeError("unsupported endpoint envelope")
            origin_entry = next(
                (entry for entry in ca_store.active_entries()
                 if unb64(entry.public_key) == origin_identity),
                None,
            )
            if origin_entry is None:
                raise EndpointEnvelopeError("NLE2 origin identity is not active in Router-CA")
            source_address = ipaddress.ip_address(addr[0])
            origin_network = ipaddress.ip_network(origin_entry.prefix, strict=False)
            if source_address.version != origin_network.version or source_address not in origin_network:
                raise EndpointEnvelopeError("endpoint-agent source address is outside its Router-CA prefix")
            metadata = verify_endpoint_envelope(
                decode_public_key(origin_entry.public_key),
                packet,
                max_clock_skew=self.cfg.max_clock_skew_seconds,
            )
            replay_key = (origin_identity, endpoint_sid)
            if replay_key not in self.endpoint_rx and len(self.endpoint_rx) >= 4096:
                raise EndpointEnvelopeError("NLE2 replay-session capacity reached")
            replay = self.endpoint_rx.setdefault(
                replay_key, ReplayWindow(self.cfg.replay_window)
            )
            if not replay.can_accept(metadata["sequence"]):
                raise EndpointEnvelopeError("NLE2 endpoint replay detected")
            if not replay.mark(metadata["sequence"]):
                raise EndpointEnvelopeError("NLE2 endpoint replay detected")

            outbound = self._session_for_destination(destination)
            if outbound is None:
                next_peer = self._peer_for_destination(destination)
                if next_peer is not None and self._peer_trusted(next_peer):
                    self._send_init(next_peer, self._original_router_ip())
                raise RelayForwardingError("authorized next-hop session unavailable for endpoint packet")
            next_peer = self.peers.get(outbound.peer_id)
            if next_peer is None:
                raise RelayForwardingError("next-hop peer configuration missing")
            next_host, next_port = endpoint(next_peer.endpoint)
            local_locator = self._original_router_ip()
            relay_packet = seal_relay_layer(
                outbound.send_key,
                outbound.session_id,
                outbound.tx_sequence,
                next_host,
                next_port,
                packet,
                previous_hop_source_locator=local_locator,
            )
            send_transparent(
                self.sock, relay_packet, destination, self.cfg.listen_port,
                local_locator,
                interface_index=socket.if_nametoindex(self.cfg.bind_interface),
            )
            outbound.tx_sequence += 1
            outbound.last_tx = time.time()
            self.stats["tx"] += 1
        except Exception as exc:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            LOG.warning("NLS endpoint-agent packet rejected from %s: %s", addr, exc)

    def _shutdown(self, *_args):
        self.running = False

    def run(self):
        if not self.cfg.enabled:
            LOG.warning("NLS is disabled in configuration; exiting")
            return
        if not ca_store.active_entries():
            LOG.warning("NLS is inactive: configure Router-CA endpoint/public-key entries first")
            return
        if not self.cfg.tun.enabled:
            LOG.warning("NLS is inactive: TUN is disabled")
            return
        if not self.cfg.bind_interface and self.cfg.listen_address in ("", "0.0.0.0", "::"):
            raise RuntimeError("NLS requires an explicit WAN bind interface or non-wildcard listen address")
        self._validate_tun_mtu()
        if self.cfg.forwarding_mode == "destination_preserving":
            if ":" not in self.cfg.listen_address:
                raise RuntimeError("destination-preserving mode currently requires an IPv6 listener")
            routes = [
                (prefix, endpoint(peer.endpoint)[0])
                for peer in self.peers.values()
                for prefix in peer.allowed_prefixes
            ]
            if not routes:
                raise RuntimeError("destination-preserving mode requires configured prefix-to-next-hop routes")
            install_tproxy(port=self.cfg.listen_port, mark=0x4, table=100)
            self.tproxy_active = True
            try:
                install_forward_routes(routes, interface=self.cfg.bind_interface, mark=0x5, table=200)
                self.forward_routes_active = True
            except Exception:
                remove_tproxy(mark=0x4, table=100)
                self.tproxy_active = False
                raise
        try:
            self._bind()
            self.tun = TunDevice(self.cfg.tun.name).open()
        except Exception:
            if self.forward_routes_active:
                remove_forward_routes(mark=0x5, table=200)
                self.forward_routes_active = False
            if self.tproxy_active:
                remove_tproxy(mark=0x4, table=100)
                self.tproxy_active = False
            raise
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
            if self.forward_routes_active:
                remove_forward_routes(mark=0x5, table=200)
                self.forward_routes_active = False
            if self.tproxy_active:
                remove_tproxy(mark=0x4, table=100)
                self.tproxy_active = False
            raise RuntimeError("unable to configure NLS TUN interface") from exc
        try:
            install_tun_routes(list(self.peers.values()), self.tun.name)
        except Exception:
            if self.tun:
                self.tun.close()
                self.tun = None
            if self.forward_routes_active:
                remove_forward_routes(mark=0x5, table=200)
                self.forward_routes_active = False
            if self.tproxy_active:
                remove_tproxy(mark=0x4, table=100)
                self.tproxy_active = False
            raise
        LOG.info("NLS TUN device ready: %s", self.tun.name)
        try:
            while self.running:
                now = time.time()
                for sid, session in list(self.sessions.items()):
                    if now - session.last_seen > self.cfg.session_timeout_seconds:
                        lsdb.remove(session.vip)
                        del self.sessions[sid]
                lsdb.expire(now)
                for sid, expires in list(self.seen_handshakes.items()):
                    if expires <= now:
                        del self.seen_handshakes[sid]
                ready, _, _ = select.select([self.sock, self.tun], [], [], 1.0)
                for item in ready:
                    if item is self.sock:
                        if self.cfg.forwarding_mode == "destination_preserving":
                            try:
                                received = recv_transparent(self.sock, max_size=MAX_DATAGRAM)
                            except Exception as exc:
                                self.stats["drops"] += 1
                                self.stats["data_drops"] += 1
                                LOG.warning("NLS transparent receive rejected: %s", exc)
                                continue
                            packet, addr = received.payload, received.peer
                            destination = received.destination_address
                            interface_index = received.interface_index
                            self._last_received_interface_index = interface_index
                        else:
                            packet, addr = self.sock.recvfrom(MAX_DATAGRAM)
                            destination = None
                            interface_index = None
                        if packet.startswith(b"NLSH"):
                            kind, _ = decode_message(packet)
                            if kind == INIT:
                                self._handle_init(packet, addr, destination, interface_index)
                            elif kind == RESPONSE:
                                self._handle_response(packet, addr, destination, interface_index)
                        elif self.cfg.forwarding_mode == "destination_preserving" and packet.startswith(b"NLR1"):
                            self._handle_relay_data(packet, addr, destination)
                        elif self.cfg.forwarding_mode == "destination_preserving" and packet.startswith(b"NLE2"):
                            self._handle_local_endpoint_packet(packet, addr, destination)
                        elif self.cfg.forwarding_mode == "legacy" and packet.startswith(b"NLE1"):
                            self._handle_data(packet, addr)
                    else:
                        try:
                            payload = self.tun.read()
                        except BlockingIOError:
                            continue
                        if payload:
                            self._send_payload(payload)

        finally:
            remove_tun_routes()
            if self.forward_routes_active:
                remove_forward_routes(mark=0x5, table=200)
                self.forward_routes_active = False
            if self.tproxy_active:
                remove_tproxy(mark=0x4, table=100)
                self.tproxy_active = False
            if self.tun:
                self.tun.close()
            for session in self.sessions.values():
                lsdb.remove(session.vip)
            if self.sock:
                self.sock.close()


def run():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    daemon = NLSDaemon(load())
    signal.signal(signal.SIGTERM, daemon._shutdown)
    signal.signal(signal.SIGINT, daemon._shutdown)
    daemon.run()
