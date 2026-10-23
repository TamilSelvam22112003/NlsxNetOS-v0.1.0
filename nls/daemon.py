import ipaddress
import json
import logging
import os
import select
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import load
from .encapsulation import HEADER, HEADER_SIZE
from .source_token import open_source_token_payload, seal_source_token_payload
from .identity import load_or_create, public_key_b64, unb64
from . import lsdb
from .replay import ReplayWindow
from .rsa import load_or_create as load_rsa_private_key
from .routing import install_tun_routes, remove_tun_routes
from .tun import TunDevice
from .v2_runtime import HandshakeV2

LOG = logging.getLogger("nlsxnetos.nls")
STATUS_PATH = Path(os.environ.get("NLSXNETOS_NLS_STATUS_PATH", "/run/nlsxnetos/nls-status.json"))
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
    state: str = "ESTABLISHED"
    created_mono: float = field(default_factory=time.monotonic)
    overlap_until: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    peer_certificate_serial: str = ""
    peer_record_seq: int = 0
    peer_record: dict = field(default_factory=dict)
    local_record: dict = field(default_factory=dict)
    send_token: str = ""
    recv_token: str = ""
    token_lease: object = field(default=None, repr=False, compare=False)
    key_lock: object = field(default_factory=threading.RLock, repr=False, compare=False)


class NLSDaemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.identity = load_or_create(cfg.identity_key)
        self.identity_public = public_key_b64(self.identity)
        self.identity_raw = unb64(self.identity_public)
        # RSA remains a handshake-envelope key only; NLE2 DATA never wraps per-packet keys.
        self.encryption_private_key = load_rsa_private_key(cfg.encryption_private_key)
        self.sock = None
        self.tun = None
        self.peers = {p.id: p for p in cfg.peers}
        self.sessions = {}
        self.source_token_sessions = {}
        self.source_token_reserved = set()
        self.source_token_lock = threading.RLock()
        self.pending_payloads = {}
        self.max_pending_payloads = 64
        self.running = True
        self.reason_counters = {}
        # Compiled operator longest-prefix routes are refreshed on a bounded timer,
        # not statted, parsed, or network-constructed for every packet.
        self._operator_route_cache = {4: {}, 6: {}}
        self._operator_route_prefix_lengths = {4: (), 6: ()}
        self._operator_route_config_signature = None
        self._operator_route_refresh_at = 0.0
        self._operator_route_cache_lock = threading.RLock()
        self.stats = {
            "handshakes": 0,
            "established": 0,
            "rx": 0,
            "tx": 0,
            "drops": 0,
            "data_drops": 0,
        }
        self.v2 = HandshakeV2(self)

    def _log_drop(self, reason, source="unknown", stage="data", error_type=None, error_field=None, error_code=None, error_site=None, **context):
        """Emit a stable JSON drop event without packet contents or exception text.

        Trust diagnostics are explicitly allow-listed and numeric. This accepts the
        sequence/freshness context supplied by lifecycle callers without allowing
        arbitrary values (or secrets) into structured logs.
        """
        counters = getattr(self, "reason_counters", None)
        if not isinstance(counters, dict):
            counters = {}
            self.reason_counters = counters
        counters[reason] = counters.get(reason, 0) + 1
        event = {
            "event": "nls_drop", "reason": reason, "stage": stage,
            "source": str(source), "time": int(time.time()),
        }
        if error_type:
            event["error_type"] = str(error_type)
        if error_field:
            event["error_field"] = str(error_field)
        if error_code:
            event["error_code"] = str(error_code)
        if error_site:
            event["error_site"] = str(error_site)
        for field_name in (
            "stored_record_seq", "incoming_record_seq",
            "stored_directory_seq", "incoming_directory_seq",
            "bundle_expires_at", "seconds_since_sync",
        ):
            value = context.get(field_name)
            if type(value) is int:
                event[field_name] = value
        LOG.warning(json.dumps(event, sort_keys=True, separators=(",", ":")))

    @staticmethod
    def _zeroize_session(session):
        """Wait for packet users to release the session before zeroizing key buffers."""
        with session.key_lock:
            for name in ("send_key", "recv_key"):
                value = getattr(session, name, None)
                if isinstance(value, bytearray):
                    for index in range(len(value)):
                        value[index] = 0
                elif isinstance(value, bytes):
                    # Immutable bytes cannot be overwritten in place; replace the
                    # reference while documenting that prior copies may remain.
                    setattr(session, name, bytearray(len(value)))
            session.state = "CLOSED"

    def _mark_sessions_for_overlap(self, peer_id, new_session_id=None, now_mono=None):
        now_mono = time.monotonic() if now_mono is None else now_mono
        until = now_mono + self.cfg.rekey_overlap_seconds
        for sid, session in self.sessions.items():
            if sid != new_session_id and session.peer_id == peer_id and session.state in ("ESTABLISHED", "OVERLAP"):
                session.state = "OVERLAP"
                session.overlap_until = until
                # Keep the on-disk vIP/SourceToken table aligned with the
                # make-before-break session state. The row remains resolvable
                # during overlap so delayed packets can still be accepted.
                for token in (getattr(session, "recv_token", ""), getattr(session, "send_token", "")):
                    if not token:
                        continue
                    try:
                        lsdb.set_state(token, "OVERLAP")
                    except Exception as exc:
                        self._log_drop(
                            "NLS_LSDB_OVERLAP_STATE_FAILED",
                            source=session.endpoint[0], stage="session-lifecycle",
                            error_type=type(exc).__name__,
                        )

    def _remove_session(self, sid, reason):
        session = self.sessions.pop(sid, None)
        if session is None:
            return None
        if session.vip:
            # Session teardown removes LSDB/vIP rows only for this session, so
            # a stale cleanup cannot delete a newer rekeyed session's mapping.
            lsdb.remove(session.vip, session_id=sid)
        for token in (getattr(session, "send_token", ""), getattr(session, "recv_token", "")):
            if token:
                lsdb.remove(token, session_id=sid)
        if not hasattr(self, "source_token_lock"):
            self.source_token_lock = threading.RLock()
        if not hasattr(self, "source_token_sessions"):
            self.source_token_sessions = {}
        if not hasattr(self, "source_token_reserved"):
            self.source_token_reserved = set()
        lease_closed = True
        lease = getattr(session, "token_lease", None)
        if lease is not None:
            try:
                lease.close()
            except Exception as exc:
                lease_closed = False
                self._log_drop(
                    "NLS_SOURCE_TOKEN_CLEANUP_FAILED", source=session.endpoint[0],
                    stage="session-lifecycle", error_type=type(exc).__name__,
                )
        with self.source_token_lock:
            recv_token = getattr(session, "recv_token", "")
            if self.source_token_sessions.get(recv_token) == sid:
                self.source_token_sessions.pop(recv_token, None)
            if lease_closed:
                self.source_token_reserved.discard(getattr(session, "send_token", ""))
                self.source_token_reserved.discard(recv_token)
        self._zeroize_session(session)
        self._log_drop(reason, source=session.endpoint[0], stage="session-lifecycle")
        return session

    def _remove_all_sessions(self, reason):
        for sid in list(self.sessions):
            self._remove_session(sid, reason)

    def _abort_pending_handshakes(self, reason, peer_id=None):
        """Abort in-flight handshakes when CA trust changes or becomes unavailable.

        Active-session teardown alone is insufficient: an in-flight M2/M3/M4
        exchange must not install a session after the local trust state has
        rejected that peer. The handshake runtime owns vIP/socket cleanup.
        """
        runtime = getattr(self, "v2", None)
        pending = getattr(runtime, "pending", None)
        if not isinstance(pending, dict):
            return
        for session_id, state in list(pending.items()):
            if peer_id is not None and state.get("peer_id") != peer_id:
                continue
            source_addr = state.get("source_addr")
            runtime._abort(session_id, reason, source_addr)

    def _publish_status(self, directory_freshness_seconds=-1):
        now_mono = time.monotonic()
        snapshot = {
            "updated_at": int(time.time()),
            "router_id": self.cfg.router_id,
            "directory_freshness_seconds": int(directory_freshness_seconds),
            "counters": dict(self.stats),
            "reason_counters": dict(self.reason_counters),
            "sessions": [
                {
                    "peer": session.peer_id,
                    "session_id": session.session_id.hex(),
                    "state": session.state,
                    "bytes_sent": session.bytes_sent,
                    "bytes_received": session.bytes_received,
                    "packets_sent": session.packets_sent,
                    "packets_received": session.packets_received,
                    "rekey_age_seconds": max(0, int(now_mono - session.created_mono)),
                    "ca_freshness_seconds": int(directory_freshness_seconds),
                }
                for session in self.sessions.values()
            ],
        }
        try:
            STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
            temp = STATUS_PATH.with_suffix(".tmp")
            temp.write_text(json.dumps(snapshot, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            temp.replace(STATUS_PATH)
        except OSError:
            self._log_drop("NLS_STATUS_WRITE_FAILED", stage="operations")

    def _refresh_session_trust(self):
        """Tear down sessions when the verified directory or either RDR is no longer trusted."""
        from . import ca_client

        settings = None
        verified_payload = None
        try:
            settings = self.v2._settings()
            if getattr(settings, "trust_mode", "ca") != "offline" and ca_client.heartbeat_freshness(settings) < 0:
                raise RuntimeError("Router-CA heartbeat freshness lost")
            _cache, verified_payload = ca_client._load_verified_cache(settings)
            if verified_payload is None:
                freshness = -1
            else:
                remaining = int(verified_payload.get("expires_at", 0)) - int(time.time())
                freshness = remaining if remaining > 0 else -1
        except Exception as exc:
            # Log only numeric trust metadata; never serialize envelopes, keys, tokens,
            # peer payloads, or the exception text. This identifies stale refresh vs rollback.
            diag = ca_client.trust_diagnostics(settings) if settings is not None else {}
            self._log_drop(
                "NLS_CA_FRESHNESS_LOST", stage="session-lifecycle",
                error_type=type(exc).__name__, **diag,
            )
            self._abort_pending_handshakes("NLS_CA_FRESHNESS_LOST")
            self._remove_all_sessions("NLS_CA_FRESHNESS_LOST")
            return -1
        if freshness < 0:
            self._abort_pending_handshakes("NLS_CA_FRESHNESS_LOST")
            self._remove_all_sessions("NLS_CA_FRESHNESS_LOST")
            return -1
        try:
            local_record = self.v2._cached_record(self.cfg.router_id)
        except Exception:
            self._abort_pending_handshakes("NLS_LOCAL_STATUS_INVALID")
            self._remove_all_sessions("NLS_LOCAL_STATUS_INVALID")
            return -1
        if local_record.get("status") != "ACTIVE":
            self._abort_pending_handshakes("NLS_LOCAL_STATUS_INVALID")
            self._remove_all_sessions("NLS_LOCAL_STATUS_INVALID")
            return -1
        try:
            if ca_client.is_revoked(str(local_record.get("certificate_serial", "")), settings):
                self._abort_pending_handshakes("NLS_LOCAL_CERT_REVOKED")
                self._remove_all_sessions("NLS_LOCAL_CERT_REVOKED")
                return -1
        except Exception:
            self._abort_pending_handshakes("NLS_CA_FRESHNESS_LOST")
            self._remove_all_sessions("NLS_CA_FRESHNESS_LOST")
            return -1

        # Validate pending handshakes as well as established sessions. Otherwise
        # a peer revoked during M1-M4 could retain state until the handshake timeout.
        for pending_sid, pending_state in list(getattr(self.v2, "pending", {}).items()):
            pending_peer = pending_state.get("peer_id")
            if not pending_peer:
                self.v2._abort(pending_sid, "NLS_HS_TRUST_INVALID",
                               pending_state.get("source_addr"))
                continue
            try:
                pending_record = self.v2._cached_record(pending_peer)
                if pending_record.get("status") != "ACTIVE":
                    self.v2._abort(pending_sid, "NLS_PEER_STATUS_INVALID",
                                   pending_state.get("source_addr"))
                    continue
                if ca_client.is_revoked(
                    str(pending_record.get("certificate_serial", "")), settings
                ):
                    self.v2._abort(pending_sid, "NLS_PEER_CERT_REVOKED",
                                   pending_state.get("source_addr"))
            except Exception:
                self.v2._abort(pending_sid, "NLS_CA_TRUST_INVALID",
                               pending_state.get("source_addr"))

        for sid, session in list(self.sessions.items()):
            try:
                peer_record = self.v2._cached_record(session.peer_id)
                if peer_record.get("status") != "ACTIVE":
                    self._abort_pending_handshakes("NLS_PEER_STATUS_INVALID", session.peer_id)
                    self._remove_session(sid, "NLS_PEER_STATUS_INVALID")
                    continue
                if ca_client.is_revoked(session.peer_certificate_serial, settings):
                    self._abort_pending_handshakes("NLS_PEER_CERT_REVOKED", session.peer_id)
                    self._remove_session(sid, "NLS_PEER_CERT_REVOKED")
                    continue
                if int(peer_record.get("record_seq", 0)) < session.peer_record_seq:
                    # The Router-CA client agent is a separate process and can
                    # publish a newer signed cache without invalidating this
                    # daemon's in-memory RDR snapshot. Re-read the verified disk
                    # cache once before treating a lower sequence as a real
                    # rollback; a stable regression still fails closed below.
                    ca_client.invalidate_verified_record_cache(settings)
                    peer_record = self.v2._cached_record(session.peer_id)
                if int(peer_record.get("record_seq", 0)) < session.peer_record_seq:
                    self._log_trust_sequence_failure(
                        "NLS_RDR_ROLLBACK", settings, session.peer_id,
                        session.peer_record_seq, int(peer_record.get("record_seq", 0)),
                        session.local_record, local_record, verified_payload,
                    )
                    self._remove_session(sid, "NLS_RDR_ROLLBACK")
                    continue
                self.v2.compare_fresh_record(session.peer_record, peer_record, "S3")
                if session.local_record:
                    if int(local_record.get("record_seq", 0)) < int(session.local_record.get("record_seq", 0)):
                        # As above, refresh the daemon-local RDR snapshot before
                        # deciding that the CA has rolled a signed record back.
                        ca_client.invalidate_verified_record_cache(settings)
                        local_record = self.v2._cached_record(self.cfg.router_id)
                    if int(local_record.get("record_seq", 0)) < int(session.local_record.get("record_seq", 0)):
                        self._log_trust_sequence_failure(
                            "NLS_RDR_ROLLBACK", settings, self.cfg.router_id,
                            int(session.local_record.get("record_seq", 0)),
                            int(local_record.get("record_seq", 0)),
                            session.local_record, local_record, verified_payload,
                        )
                        self._remove_session(sid, "NLS_RDR_ROLLBACK")
                        continue
                    self.v2.compare_fresh_record(session.local_record, local_record, "S4")
            except Exception as exc:
                detail = str(exc).lower()
                reason = "NLS_CA_TRUST_INVALID"
                if "revoked" in detail:
                    reason = "NLS_PEER_CERT_REVOKED"
                elif "status" in detail or "expired" in detail:
                    reason = "NLS_PEER_STATUS_INVALID"
                elif "rollback" in detail:
                    reason = "NLS_RDR_ROLLBACK"
                elif "mismatch" in detail:
                    reason = "NLS_RDR_CHANGED"
                self._remove_session(sid, reason)
        return freshness

    def _log_trust_sequence_failure(self, reason, settings, router_id, stored_record_seq, incoming_record_seq, stored_record, incoming_record, bundle_payload):
        from . import ca_client
        diag = ca_client.trust_diagnostics(settings, router_id=router_id) if settings is not None else {}
        # Merge before the call: diagnostics already contain several of these keys.
        # Passing duplicate explicit keywords alongside **diag raises TypeError.
        context = dict(diag)
        context.update({
            "stored_record_seq": int(stored_record_seq),
            "incoming_record_seq": int(incoming_record_seq),
            "stored_directory_seq": int((stored_record or {}).get("directory_seq", -1)),
            "incoming_directory_seq": int((incoming_record or {}).get("directory_seq", -1)),
            "bundle_expires_at": int((bundle_payload or {}).get("expires_at", 0)),
        })
        self._log_drop(reason, stage="session-lifecycle", **context)

    def _cleanup_sessions(self, now_mono):
        now_wall = time.time()
        for sid, session in list(self.sessions.items()):
            if session.state == "OVERLAP" and session.overlap_until and now_mono >= session.overlap_until:
                self._remove_session(sid, "NLS_REKEY_OVERLAP_ENDED")
            # A one-way but active flow updates last_tx without receiving data.
            # Treat either authenticated receive or successful transmit as activity;
            # otherwise a long UDP/TCP sender can expire its own healthy session.
            elif now_wall - max(session.last_seen, session.last_tx) > self.cfg.session_timeout_seconds:
                self._remove_session(sid, "NLS_SESSION_IDLE_TIMEOUT")

    def _start_rekey(self, session, peer, original_ip=""):
        if any(
            state.get("rekey") and state.get("peer_id") == session.peer_id
            for state in self.v2.pending.values()
        ):
            return
        try:
            self.v2.start(peer, original_ip, rekey=True)
        except Exception:
            self._log_drop("NLS_REKEY_START_FAILED", source=session.endpoint[0], stage="rekey")

    def _maybe_rekey_sessions(self, now_mono):
        packet_limit = self.cfg.rekey_packet_limit
        packet_trigger = max(1, int(packet_limit * 0.9))
        age_trigger = self.cfg.rekey_seconds * 0.9
        for session in list(self.sessions.values()):
            if session.state != "ESTABLISHED":
                continue
            if session.tx_sequence < packet_trigger and now_mono - session.created_mono < age_trigger:
                continue
            try:
                peer = self.peers.get(session.peer_id) or self.v2.peer_for_id(session.peer_id)
                self.peers[session.peer_id] = peer
                self._start_rekey(session, peer, "")
            except Exception:
                self._log_drop("NLS_REKEY_START_FAILED", source=session.endpoint[0], stage="rekey")

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
        # Request packet-info ancillary data so pre-decryption limits can be
        # keyed to the actual ingress interface rather than the claimed router.
        if family == socket.AF_INET6 and hasattr(socket, "IPV6_RECVPKTINFO"):
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        elif family == socket.AF_INET and hasattr(socket, "IP_PKTINFO"):
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
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
    
    @staticmethod
    def _ingress_interface(item, ancillary):
        for level, kind, data in ancillary:
            try:
                if level == socket.IPPROTO_IPV6 and kind == getattr(socket, "IPV6_PKTINFO", -1) and len(data) >= 20:
                    index = int.from_bytes(data[16:20], byteorder=__import__("sys").byteorder)
                elif level == socket.IPPROTO_IP and kind == getattr(socket, "IP_PKTINFO", -1) and len(data) >= 12:
                    index = int.from_bytes(data[:4], byteorder=__import__("sys").byteorder)
                else:
                    continue
                if index:
                    return socket.if_indextoname(index)
            except (OSError, ValueError):
                continue
        return ""

    def _dispatch_datagram(self, item, packet, addr, ingress_interface=""):
        """Demultiplex exact SourceTokens before the NLH2 handshake pre-check."""
        if self.v2.is_retired_vip(str(addr[0])):
            self.v2._drop("VIP_AFTER_SWITCH", addr, "S5")
            return
        try:
            source = str(ipaddress.IPv6Address(addr[0]))
        except (ValueError, TypeError):
            source = ""
        token_sessions = getattr(self, "source_token_sessions", {})
        session_id = token_sessions.get(source)
        if item is self.sock and session_id is not None:
            self._handle_data(packet, addr, session_id)
            return
        if packet.startswith(b"NLH2"):
            self.v2.handle_packet(packet, addr, item, ingress_interface=ingress_interface)
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

    def _operator_route_for_destination(self, destination):
        """Resolve a destination through precompiled operator routes.

        Route YAML is revalidated at most once per second. Each packet then performs
        only address parsing and longest-prefix comparisons against precompiled
        networks; CA RDR prefixes are never used to create routing instructions.
        """
        address = ipaddress.ip_address(destination)
        now_mono = time.monotonic()
        with self._operator_route_cache_lock:
            if now_mono >= self._operator_route_refresh_at:
                # Poll the validated config fingerprint at most once per second.
                # Keep the compiled LPM index unchanged unless route semantics change.
                self._operator_route_refresh_at = now_mono + 1.0
                from .routing import operator_routes
                try:
                    routes = operator_routes()
                except Exception:
                    # Fail closed on invalid config; never use a stale table past its
                    # refresh deadline after a failed validation.
                    self._operator_route_cache = {4: {}, 6: {}}
                    self._operator_route_prefix_lengths = {4: (), 6: ()}
                    self._operator_route_config_signature = None
                    raise
                signature = tuple(sorted(
                    (str(route["prefix"]), str(route["router_id"])) for route in routes
                ))
                if signature != self._operator_route_config_signature:
                    compiled = {4: {}, 6: {}}
                    for route in routes:
                        network = ipaddress.ip_network(route["prefix"], strict=True)
                        bits = network.max_prefixlen
                        prefixlen = network.prefixlen
                        key = int(network.network_address) >> (bits - prefixlen)
                        compiled[network.version].setdefault(prefixlen, {})[key] = route["router_id"]
                    self._operator_route_cache = compiled
                    self._operator_route_prefix_lengths = {
                        version: tuple(sorted(by_length, reverse=True))
                        for version, by_length in compiled.items()
                    }
                    self._operator_route_config_signature = signature
            by_length = self._operator_route_cache[address.version]
            prefix_lengths = self._operator_route_prefix_lengths[address.version]
        address_int = int(address)
        bits = address.max_prefixlen
        for prefixlen in prefix_lengths:
            key = address_int >> (bits - prefixlen)
            router_id = by_length[prefixlen].get(key)
            if router_id is not None:
                return router_id
        return None

    def _refresh_ca_peer(self, destination):
        # Peer discovery is based on a verified RDR; CA prefixes never create routes.
        try:
            peer_id = self._operator_route_for_destination(destination)
            if peer_id is None:
                return None
            peer = self.v2.peer_for_id(peer_id)
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

    @staticmethod
    def _safe_exception_site(exc):
        """Return only the final code location, never exception text or locals."""
        tb = exc.__traceback__
        while tb is not None and tb.tb_next is not None:
            tb = tb.tb_next
        if tb is None:
            return None
        return f"{tb.tb_frame.f_code.co_name}:{tb.tb_lineno}"

    @staticmethod
    def _safe_data_error_code(exc):
        """Map known internal failures to stable codes without logging exception text."""
        detail = str(exc).lower()
        known = (
            ("router-ca cache state changed during verification", "CA_CACHE_STATE_CHANGED"),
            ("verified router-ca directory cache is invalid", "CA_CACHE_INVALID"),
            ("router-ca rollback mark", "CA_ROLLBACK_MARK_INVALID"),
            ("cached router-ca directory freshness expired", "CA_CACHE_EXPIRED"),
            ("no signed cached router-ca record", "CA_RECORD_MISSING"),
            ("cached router-ca record is stale", "CA_RECORD_STALE"),
            ("cached router-ca record is not active", "CA_RECORD_INACTIVE"),
            ("cached router-ca record is revoked", "CA_RECORD_REVOKED"),
            ("verified router-ca directory cache is unavailable", "CA_CACHE_UNAVAILABLE"),
            ("unable to stat verified router-ca cache state", "CA_CACHE_STAT_FAILED"),
            ("unable to read router-ca revocation state", "CA_REVOCATION_STATE_UNREADABLE"),
            ("unable to read router-ca policy state", "CA_POLICY_STATE_UNREADABLE"),
            ("router-ca directory signature verification failed", "CA_SIGNATURE_INVALID"),
            ("router-ca directory freshness expired", "CA_DIRECTORY_EXPIRED"),
            ("signed lookup/cache record mismatch", "CA_LOOKUP_CACHE_MISMATCH"),
        )
        for needle, code in known:
            if needle in detail:
                return code
        return "RUNTIME_ERROR_UNCLASSIFIED" if isinstance(exc, RuntimeError) else None

    def _handle_data(self, packet, addr, source_token_session_id=None):
        """Authenticate SourceToken data; legacy NLE2 packets are never a fallback."""
        if self.v2.is_retired_vip(str(addr[0])):
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            LOG.warning(json.dumps({
                "event": "nls_drop", "reason": "VIP_AFTER_SWITCH",
                "stage": "data", "source": str(addr[0]), "time": int(time.time()),
            }, sort_keys=True, separators=(",", ":")))
            return
        try:
            if len(packet) < 8 + 1 + 16:
                raise ValueError("SourceToken DATA packet too short")
            source = str(ipaddress.IPv6Address(addr[0]))
            token_sessions = getattr(self, "source_token_sessions", {})
            sid = source_token_session_id or token_sessions.get(source)
            session = self.sessions.get(sid) if sid is not None else None
            if (session is None or session.state not in ("ESTABLISHED", "OVERLAP")
                    or source != session.recv_token):
                raise ValueError("unknown SourceToken session")
            counter = int.from_bytes(packet[:8], "big")
            if not session.recv_replay.can_accept(counter):
                raise ValueError("SourceToken replay detected")
            local_original_ip = session.local_record.get("originalIP")
            if not isinstance(local_original_ip, str):
                raise ValueError("local RDR originalIP missing")
            authenticated_counter, message_type, result = open_source_token_payload(
                bytes(session.recv_key), session.recv_iv_prefix, packet,
                source, local_original_ip,
            )
            if authenticated_counter != counter:
                raise ValueError("SourceToken counter mismatch")
            # Commit replay state only after AEAD authentication and IP validation.
            if not session.recv_replay.mark(counter):
                raise ValueError("SourceToken replay detected")
            if message_type != 0:
                raise ValueError("SourceToken message type is unassigned")
            if self.cfg.enforce_inner_source_prefix:
                self._validate_inner_source_prefix(session.peer_id, result)
            self._validate_inner_destination_prefix(result)
            if self.tun is None:
                raise ValueError("NLS data plane requires the TUN interface")
            self.tun.write(result)
            self.stats["rx"] += 1
            session.bytes_received += len(result)
            session.packets_received += 1
            session.last_seen = time.time()
        except Exception as exc:
            self.stats["drops"] += 1
            self.stats["data_drops"] += 1
            reason = "NLS_DATA_PACKET_REJECTED"
            detail = str(exc).lower()
            if "inner_src_not_allowed" in detail:
                reason = "NLS_DATA_INNER_SRC_NOT_ALLOWED"
            elif "inner_dst_not_allowed" in detail:
                reason = "NLS_DATA_INNER_DST_NOT_ALLOWED"
            elif "replay" in detail:
                reason = "NLS_REPLAY_DUPLICATE"
            elif "unknown sourcetoken session" in detail:
                reason = "NLS_DATA_SESSION_INVALID"
            elif "too short" in detail or "length invalid" in detail:
                reason = "NLS_DATA_FORMAT_INVALID"
            elif "authentication" in detail or "decrypt" in detail or "tag" in detail:
                reason = "NLS_DATA_AUTH_INVALID"
            self._log_drop(
                reason, source=addr[0], stage="data",
                error_type=f"{type(exc).__module__}.{type(exc).__name__}",
                error_code=self._safe_data_error_code(exc),
                error_site=self._safe_exception_site(exc),
            )

    def _peer_for_destination(self, destination):
        # Only explicit operator routes select a peer. RDR prefixes are authorization
        # metadata and are never installed or consulted as routing instructions.
        try:
            peer_id = self._operator_route_for_destination(destination)
        except Exception as exc:
            self._log_drop(
                "NLS_ROUTE_CONFIG_INVALID", stage="route-selection",
                error_type=f"{type(exc).__module__}.{type(exc).__name__}",
            )
            return None
        if peer_id is None:
            return None
        peer = self.peers.get(peer_id)
        if peer is None:
            try:
                peer = self.v2.peer_for_id(peer_id)
            except Exception as exc:
                # A configured route with an unavailable/untrusted RDR is not the
                # same condition as an absent operator route. Keep the failure closed
                # but emit the accurate reason for diagnostics.
                self._log_drop(
                    "NLS_ROUTE_PEER_LOOKUP_FAILED", stage="peer-validation",
                    error_type=getattr(
                        exc, "cause_type",
                        f"{type(exc).__module__}.{type(exc).__name__}",
                    ),
                    error_field=getattr(exc, "field_name", None),
                )
                return None
            self.peers[peer_id] = peer
        return peer

    def _session_for_destination(self, destination):
        peer = self._peer_for_destination(destination)
        if peer is None:
            return None
        if not peer.encryption_public_key:
            return None
        sessions = [s for s in self.sessions.values() if s.peer_id == peer.id and s.state == "ESTABLISHED"]
        return max(sessions, key=lambda s: s.created_mono) if sessions else None

    def _queue_for_handshake(self, peer, payload, rekey=False):
        queue = self.pending_payloads.setdefault(peer.id, [])
        if len(queue) >= self.max_pending_payloads:
            queue.pop(0)
            self.stats["drops"] += 1
        queue.append(payload)
        # One pending NLH2 exchange per peer is sufficient. In particular, do
        # not launch a second rekey for every packet that arrives at the hard
        # limit while the first make-before-break handshake is still pending.
        pending_for_peer = any(
            state.get("peer_id") == peer.id
            for state in self.v2.pending.values()
        )
        if not pending_for_peer:
            self._send_init(peer, "", rekey=rekey)

    def _flush_pending(self, peer_id):
        queue = self.pending_payloads.pop(peer_id, [])
        for payload in queue:
            try:
                self._send_payload(payload)
            except Exception:
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
        # The key lock serializes packet use against teardown/zeroization. A
        # concurrent rekey cleanup cannot overwrite a key while AEAD or sendto
        # is still using it.
        with session.key_lock:
            if session.state not in ("ESTABLISHED", "OVERLAP"):
                self._queue_for_handshake(peer, payload, rekey=True)
                return False
            if (session.tx_sequence >= max(1, int(self.cfg.rekey_packet_limit * 0.9))
                    or time.monotonic() - session.created_mono >= self.cfg.rekey_seconds * 0.9):
                self._start_rekey(session, peer, destination)
            if session.tx_sequence >= self.cfg.rekey_packet_limit:
                self._log_drop("NLS_REKEY_REQUIRED", stage="send")
                self._queue_for_handshake(peer, payload, rekey=True)
                return False
            packet = seal_source_token_payload(
                bytes(session.send_key),
                session.send_iv_prefix,
                session.tx_sequence,
                session.send_token,
                session.endpoint[0],
                payload,
            )
            if session.token_lease is None:
                raise RuntimeError("SourceToken sender socket is unavailable")
            session.tx_sequence += 1
            session.token_lease.sock.sendto(packet, session.endpoint)
            session.last_tx = time.time()
            session.bytes_sent += len(payload)
            session.packets_sent += 1
            self.stats["tx"] += 1
            return True

    def _send_init(self, peer, original_ip, rekey=False):
        """Start only the NLH2 v2 handshake; legacy NLSH INIT is disabled."""
        return self.v2.start(peer, original_ip, rekey=rekey)

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
        next_trust_check = 0.0
        next_status_publish = 0.0
        directory_freshness = -1
        while self.running:
            now_mono = time.monotonic()
            if now_mono >= next_trust_check:
                directory_freshness = self._refresh_session_trust()
                # The separate Router-CA client agent heartbeats on its configured
                # interval; poll its verified cache twice per second so revocation or
                # freshness-loss teardown adds at most 500 ms of local polling delay.
                next_trust_check = now_mono + 0.5
            self._cleanup_sessions(now_mono)
            self._maybe_rekey_sessions(now_mono)
            if now_mono >= next_status_publish:
                self._publish_status(directory_freshness)
                next_status_publish = now_mono + 1
            # Use the LSDB's signature/lease-aware snapshot cache in the
            # packet loop. Passing an explicit timestamp disables that cache
            # and re-parses every entry for every received datagram.
            lsdb.expire()
            self.v2.expire(now_mono)
            ready, _, _ = select.select([self.sock, self.tun, *self.v2.sockets()], [], [], 0.5)
            for item in ready:
                if item is self.tun:
                    try:
                        payload = self.tun.read()
                    except BlockingIOError:
                        continue
                    if payload:
                        self._send_payload(payload)
                    continue
                ancillary_size = 0
                if item.family == socket.AF_INET6 and hasattr(socket, "IPV6_PKTINFO"):
                    ancillary_size += socket.CMSG_SPACE(20)
                if item.family == socket.AF_INET and hasattr(socket, "IP_PKTINFO"):
                    ancillary_size += socket.CMSG_SPACE(12)
                packet, ancillary, _flags, addr = item.recvmsg(MAX_DATAGRAM, ancillary_size)
                ingress_interface = self._ingress_interface(item, ancillary)
                self._dispatch_datagram(item, packet, addr, ingress_interface)
        self.v2.close()
        self._remove_all_sessions("NLS_SESSION_SHUTDOWN")
        remove_tun_routes()
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
