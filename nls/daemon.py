import ipaddress
import json
import logging
import select
import signal
import socket
import subprocess
import time
from dataclasses import dataclass

from security.trust.router_ca import store as ca_store
from .config import PeerConfig, load
from .encapsulation import HEADER, HEADER_SIZE, MAGIC as DATA_MAGIC, open_ip_packet, seal_ip_packet
from .identity import load_or_create, public_key_b64, unb64
from . import lsdb
from .replay import ReplayWindow
from .routing import install_tun_routes, remove_tun_routes
from .tun import TunDevice
from .v2_runtime import HandshakeV2

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
    send_iv_prefix: bytes
    recv_iv_prefix: bytes
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
        self.sock = None
        self.tun = None
        self.peers = {p.id: p for p in cfg.peers}
        self.sessions = {}
        self.pending_payloads = {}
        self.max_pending_payloads = 64
        self.v2 = HandshakeV2(self)
        self.running = True
        self.stats = {
            "handshakes": 0,
            "established": 0,
            "rx": 0,
            "tx": 0,
            "drops": 0,
            "data_drops": 0,
        }

    def _log_drop(self, reason, source="unknown", stage="data"):
        """Emit a stable JSON drop event without packet contents or exception text."""
        LOG.warning(json.dumps({
            "event": "nls_drop", "reason": reason, "stage": stage,
            "source": str(source), "time": int(time.time()),
        }, sort_keys=True, separators=(",", ":")))

    def _peer_trusted(self, peer):
        try:
            record = self.v2._cached_record(peer.id)
            record_rsa = __import__("cryptography.hazmat.primitives.serialization", fromlist=["load_pem_public_key"]).load_pem_public_key(
                record["rsa_encryption_public_key"].encode("ascii")
            )
            import base64
            peer_rsa = __import__("cryptography.hazmat.primitives.serialization", fromlist=["load_der_public_key"]).load_der_public_key(
                base64.b64decode(peer.encryption_public_key, validate=True)
            )
            return (
                record.get("status") == "ACTIVE"
                and record.get("ed25519_public_key") == peer.public_key
                and record_rsa.public_numbers() == peer_rsa.public_numbers()
            )
        except Exception:
            self._log_drop("NLS_AUTH_RDR_INVALID", stage="peer-validation")
            return False

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
        # IPv6 + UDP + 32-byte NLE2 header + AES-GCM tag.
        overhead = 40 + 8 + HEADER_SIZE + 16
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
    
    def _dispatch_datagram(self, item, packet, addr):
        """Dispatch NLH2 handshakes and NLE2 data; reject legacy data formats."""
        if self.v2.is_retired_vip(str(addr[0])):
            self.v2._drop("VIP_AFTER_SWITCH", addr, "S5")
            return
        if packet.startswith(b"NLH2"):
            self.v2.handle_packet(packet, addr, item)
            return
        if item is self.sock and packet.startswith(DATA_MAGIC):
            self._handle_data(packet, addr)
            return
        self.v2._drop("NLS_HS_UNKNOWN_DATAGRAM", addr)
        try:
            payload = self.tun.read()
        except BlockingIOError:
            return
        if payload:
            self._send_payload(payload)

    def _handle_init(self, packet, addr):
        """Reject the retired cleartext NLSH INIT format; NLH2 is the only handshake."""
        self.stats["drops"] += 1
        self._log_drop("NLS_HS_LEGACY_INIT_REJECTED", source=addr[0], stage="legacy-disabled")

    def _handle_response(self, packet, addr):
        """Reject the retired cleartext NLSH RESPONSE format; NLH2 is the only handshake."""
        self.stats["drops"] += 1
        self._log_drop("NLS_HS_LEGACY_RESPONSE_REJECTED", source=addr[0], stage="legacy-disabled")

    @staticmethod
    def _packet_sequence(packet):
        if len(packet) < HEADER.size:
            raise ValueError("NLS encapsulated packet is too short")
        return HEADER.unpack(packet[:HEADER.size])[4]

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
        # Peer discovery is based on a verified RDR; CA prefixes never create routes.
        try:
            routes = __import__("nls.routing", fromlist=["operator_routes"]).operator_routes()
            address = ipaddress.ip_address(destination)
            matches = []
            for route in routes:
                network = ipaddress.ip_network(route["prefix"], strict=True)
                if network.version == address.version and address in network:
                    matches.append((network.prefixlen, route["router_id"]))
            if not matches:
                return None
            matches.sort(reverse=True)
            peer = self.v2.peer_for_id(matches[0][1])
            self.peers[peer.id] = peer
            return peer
        except Exception:
            return None

    @staticmethod
    def _inner_addresses(packet):
        if not packet:
            raise ValueError("NLE2 inner packet is empty")
        version = packet[0] >> 4
        if version == 4:
            if len(packet) < 20:
                raise ValueError("NLE2 inner IPv4 packet is too short")
            return ipaddress.ip_address(packet[12:16]), ipaddress.ip_address(packet[16:20])
        if version == 6:
            if len(packet) < 40:
                raise ValueError("NLE2 inner IPv6 packet is too short")
            return ipaddress.ip_address(packet[8:24]), ipaddress.ip_address(packet[24:40])
        raise ValueError("NLE2 inner IP version invalid")

    @staticmethod
    def _address_in_prefixes(address, prefixes):
        if not isinstance(prefixes, list) or not prefixes:
            return False
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except (TypeError, ValueError):
                continue
            if network.version == address.version and address in network:
                return True
        return False

    def _validate_inner_source_prefix(self, peer_id, packet):
        source, _destination = self._inner_addresses(packet)
        record = self.v2._cached_record(peer_id)
        if not self._address_in_prefixes(source, record.get("prefixes")):
            raise ValueError("INNER_SRC_NOT_ALLOWED")

    def _validate_inner_destination_prefix(self, packet):
        _source, destination = self._inner_addresses(packet)
        record = self.v2._cached_record(self.cfg.router_id)
        if not self._address_in_prefixes(destination, record.get("prefixes")):
            raise ValueError("INNER_DST_NOT_ALLOWED")

    def _handle_data(self, packet, addr):
        if self.v2.is_retired_vip(str(addr[0])):
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            LOG.warning(json.dumps({
                "event": "nls_drop", "reason": "VIP_AFTER_SWITCH",
                "stage": "data", "source": str(addr[0]), "time": int(time.time()),
            }, sort_keys=True, separators=(",", ":")))
            return
        try:
            if len(packet) < HEADER.size + 16:
                raise ValueError("NLS DATA packet too short")
            sid = HEADER.unpack(packet[:HEADER.size])[3]
            session = self.sessions.get(sid)
            if session is None or session.endpoint[0] != addr[0] or session.endpoint[1] != addr[1]:
                raise ValueError("unknown NLS session")
            sequence = self._packet_sequence(packet)
            if not session.recv_replay.can_accept(sequence):
                raise ValueError("NLS replay detected")
            result = open_ip_packet(
                session.recv_key,
                packet,
                session.session_id,
                session.recv_iv_prefix,
            )
            # Commit replay state only after successful AEAD authentication.
            if not session.recv_replay.mark(sequence):
                raise ValueError("NLS replay detected")
            if self.cfg.enforce_inner_source_prefix:
                self._validate_inner_source_prefix(session.peer_id, result)
            self._validate_inner_destination_prefix(result)
            if self.tun is None:
                raise ValueError("NLS data plane requires the TUN interface")
            self.tun.write(result)
            self.stats["rx"] += 1
            session.last_seen = time.time()
        except Exception as exc:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            reason = "NLS_DATA_PACKET_REJECTED"
            detail = str(exc).lower()
            if "inner_src_not_allowed" in detail:
                reason = "INNER_SRC_NOT_ALLOWED"
            elif "inner_dst_not_allowed" in detail:
                reason = "INNER_DST_NOT_ALLOWED"
            elif "replay" in detail:
                reason = "NLS_REPLAY_DUPLICATE"
            elif "unknown nls session" in detail:
                reason = "NLS_DATA_SESSION_INVALID"
            elif "too short" in detail:
                reason = "NLS_DATA_FORMAT_INVALID"
            elif "authentication" in detail or "decrypt" in detail or "tag" in detail:
                reason = "NLS_DATA_AUTH_INVALID"
            self._log_drop(reason, source=addr[0], stage="data")

    def _peer_for_destination(self, destination):
        # Only explicit operator routes select a peer. RDR prefixes are authorization
        # metadata and are never installed or consulted as routing instructions.
        address = ipaddress.ip_address(destination)
        try:
            from .routing import operator_routes
            candidates = []
            for route in operator_routes():
                network = ipaddress.ip_network(route["prefix"], strict=True)
                if network.version == address.version and address in network:
                    candidates.append((network.prefixlen, route["router_id"]))
            if not candidates:
                return None
            candidates.sort(key=lambda item: item[0], reverse=True)
            peer_id = candidates[0][1]
            peer = self.peers.get(peer_id)
            if peer is None:
                peer = self.v2.peer_for_id(peer_id)
                self.peers[peer_id] = peer
            return peer
        except Exception:
            return None

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
        self._send_init(peer, "")

    def _flush_pending(self, peer_id):
        queue = self.pending_payloads.pop(peer_id, [])
        for payload in queue:
            try:
                self._send_payload(payload)
            except Exception as exc:
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                self._log_drop("NLS_DATA_SEND_FAILED", stage="queue-flush")

    def _send_payload(self, payload):
        destination = self._packet_destination(payload)
        # IPv6 link-local multicast (for example ff02::1/ff02::2) is scoped to a LAN.
        # It must remain on the local interface and cannot be routed through a unicast NLS peer.
        # Drop only multicast from the NLS TUN path; ordinary LAN IPv6 ND/RA stays on the LAN.
        address = ipaddress.ip_address(destination)
        if address.version == 6 and address.is_multicast:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            self._log_drop("NLS_DATA_MULTICAST_NOT_TUNNELED", stage="route-selection")
            return False
        session = self._session_for_destination(destination)
        if session is None:
            peer = self._peer_for_destination(destination)
            if peer is None:
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                self._log_drop("NLS_ROUTE_NOT_OPERATOR_CONFIGURED", stage="route-selection")
                return False
            if not self._peer_trusted(peer):
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                self._log_drop("NLS_AUTH_RDR_INVALID", stage="peer-validation")
                return False
            if not peer.encryption_public_key:
                self.stats["drops"] += 1
                self.stats["data_drops"] += 1
                self._log_drop("NLS_DATA_PEER_KEY_MISSING", stage="send")
                return False
            self._queue_for_handshake(peer, payload)
            return False
        if not session.peer_id:
            raise ValueError("NLS session has no destination peer")
        peer = self.peers.get(session.peer_id)
        if peer is None:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            self._log_drop("NLS_DATA_PEER_KEY_MISSING", stage="send")
            return False
        if session.tx_sequence >= (1 << 32):
            self._log_drop("NLS_REKEY_REQUIRED", stage="send")
            self.v2.start(peer, destination)
            return False
        packet = seal_ip_packet(
            session.send_key,
            session.session_id,
            session.tx_sequence,
            session.send_iv_prefix,
            payload,
        )
        session.tx_sequence += 1
        self.sock.sendto(packet, session.endpoint)
        session.last_tx = time.time()
        self.stats["tx"] += 1
        return True

    def _send_init(self, peer, original_ip):
        """Start only the NLH2 v2 handshake; legacy NLSH INIT is disabled."""
        return self.v2.start(peer, original_ip)

    def _shutdown(self, *_args):
        self.running = False

    def run(self):
        if not self.cfg.enabled:
            LOG.warning("NLS is disabled in configuration; exiting")
            return
        if not self.cfg.tun.enabled:
            LOG.warning("NLS is inactive: TUN is disabled")
            return
        self.v2.startup_cleanup()
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
            self.v2.expire(time.monotonic())
            ready, _, _ = select.select([self.sock, self.tun, *self.v2.sockets()], [], [], 1.0)
            for item in ready:
                if item is self.tun:
                    try:
                        payload = self.tun.read()
                    except BlockingIOError:
                        continue
                    if payload:
                        self._send_payload(payload)
                    continue
                packet, addr = item.recvfrom(MAX_DATAGRAM)
                self._dispatch_datagram(item, packet, addr)
        self.v2.close()
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
