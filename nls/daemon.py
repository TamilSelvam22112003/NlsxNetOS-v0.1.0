import ipaddress
import logging
import select
import signal
import socket
import subprocess
import time
from dataclasses import dataclass

from security.trust.router_ca import store as ca_store
from .config import PeerConfig, endpoint, load
from .encapsulation import HEADER, open_ip_packet, seal_ip_packet
from .handshake import INIT, RESPONSE, decode_message, encode_message, initiator_key, new_init, responder_key
from .identity import load_or_create, public_key_b64, unb64
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
        # Worst case for the 3072-bit RSA-OAEP wrapped AES data key.
        overhead = 40 + 8 + HEADER.size + 384 + 16
        safe_mtu = mtu - overhead
        if self.cfg.tun.mtu > safe_mtu:
            raise RuntimeError(
                f"NLS TUN MTU {self.cfg.tun.mtu} exceeds safe transport MTU {safe_mtu} "
                f"for {self.cfg.bind_interface} (WAN MTU {mtu})"
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
        self.sock.sendto(encode_message(INIT, pending.init_obj), destination)
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

    def _handle_init(self, packet, addr):
        try:
            kind, obj = decode_message(packet)
            if kind != INIT:
                return
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
            self.sock.sendto(encode_message(RESPONSE, response), addr)
            self.stats["established"] += 1
            LOG.info("NLS session established with %s", peer.id)
            self._flush_pending(peer.id)
        except Exception as exc:
            self.stats["drops"] += 1
            peer = self._peer_for_obj(locals().get("obj", {}), addr) if "obj" in locals() else None
            if peer is not None:
                self._block(peer.id, str(exc))
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
        if not ca_store.active_entries():
            LOG.warning("NLS is inactive: configure Router-CA endpoint/public-key entries first")
            return
        if not self.cfg.tun.enabled:
            LOG.warning("NLS is inactive: TUN is disabled")
            return
        if not self.cfg.bind_interface and self.cfg.listen_address in ("", "0.0.0.0", "::"):
            raise RuntimeError("NLS requires an explicit WAN bind interface or non-wildcard listen address")
        self._validate_tun_mtu()
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
        LOG.info("NLS TUN device ready: %s", self.tun.name)
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
