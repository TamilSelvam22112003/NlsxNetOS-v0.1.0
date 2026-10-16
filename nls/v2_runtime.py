"""NLH2 M1-M4 handshake runtime used by NLSDaemon.

This module deliberately fails closed if a live signed Router-CA lookup,
certificate validation, policy check, or endpoint cross-check cannot complete.
The v1 packet data plane remains legacy/experimental until Prompt 4.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import json
import os
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import ca_client
from .handshake import (
    M1, M2, M3, M4, V2_HEADER, decode_v2_envelope, encode_v2_message,
    open_v2_message, sign_v2, transcript_h1, transcript_h2, transcript_h3,
    verify_timestamp, verify_v2_signature, verify_confirmation,
)
from .key_schedule import derive_session_keys
from .replay import ReplayWindow
from .vip import VIPManager


SUITE = "X25519-HKDF-SHA256-AES-256-GCM-Ed25519-RSA-OAEP-SHA256"
MAX_PENDING = 64
HANDSHAKE_TIMEOUT = 5
PENDING_REPLAY_TTL = 300
M2_MAX_DATAGRAM = 8500


def _raw_ed25519(record: dict) -> bytes:
    value = record.get("ed25519_public_key")
    if not isinstance(value, str):
        raise ValueError("RDR Ed25519 key missing")
    raw = base64.b64decode(value.encode("ascii"), validate=True)
    if len(raw) != 32:
        raise ValueError("RDR Ed25519 key length invalid")
    return raw


def _rsa_public(record: dict):
    value = record.get("rsa_encryption_public_key")
    if not isinstance(value, str):
        raise ValueError("RDR RSA key missing")
    key = serialization.load_pem_public_key(value.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072:
        raise ValueError("RDR RSA key must be RSA-3072")
    return key


def _endpoint_from_record(record: dict) -> str:
    endpoints = record.get("wan_endpoints")
    if not isinstance(endpoints, list) or not endpoints or not all(isinstance(x, str) for x in endpoints):
        raise ValueError("RDR WAN endpoint missing")
    return endpoints[0]


def _normalized_endpoint(value: str):
    from .config import endpoint
    host, port = endpoint(value)
    return str(ipaddress.ip_address(host)), port


def _record_compare_fields(record: dict) -> dict:
    fields = ("router_id", "ed25519_public_key", "rsa_encryption_public_key",
              "wan_endpoints", "gateway_ips", "prefixes", "certificate_serial",
              "status", "record_seq")
    return {field: record.get(field) for field in fields}


class HandshakeV2:
    def __init__(self, owner):
        self.owner = owner
        self.log = logging.getLogger("nlsxnetos.nls")
        self.pending: dict[bytes, dict] = {}
        self.seen: dict[bytes, float] = {}
        self.buckets: dict[str, tuple[float, float]] = {}
        self.vip_sockets: dict[bytes, object] = {}
        self.settings = None
        self.vip = None
        if owner.cfg.bind_interface:
            self.vip = VIPManager(owner.cfg.bind_interface)

    def sockets(self):
        return list(self.vip_sockets.values())

    def _settings(self):
        if self.settings is None:
            path = os.environ.get("NLS_ROUTER_CA_CONFIG") or os.environ.get("NLSXNETOS_ROUTER_CA_CLIENT_CONFIG", "/etc/nlsxnetos/router-ca-client.yaml")
            settings = ca_client.ClientSettings.load(path)
            if settings.router_id != self.owner.cfg.router_id:
                raise RuntimeError("Router-CA client router_id does not match NLS router_id")
            self.settings = settings
        return self.settings

    def _drop(self, reason: str, addr=None, stage="unknown"):
        self.owner.stats["drops"] += 1
        source = str(addr[0]) if isinstance(addr, tuple) and addr else "unknown"
        # Do not include raw packets, keys, certificates, tokens, plaintext, or exceptions.
        self.log.warning(json.dumps({
            "event": "nls_drop", "reason": reason, "stage": stage,
            "source": source, "time": int(time.time()),
        }, sort_keys=True, separators=(",", ":")))

    def _allow_source(self, addr) -> bool:
        source = str(addr[0])
        now = time.monotonic()
        tokens, last = self.buckets.get(source, (10.0, now))
        tokens = min(10.0, tokens + (now - last) * 2.0)
        if tokens < 1.0:
            self.buckets[source] = (tokens, now)
            return False
        self.buckets[source] = (tokens - 1.0, now)
        return True

    def _record_envelope(self, router_id: str) -> tuple[dict, dict]:
        settings = self._settings()
        record = ca_client.lookup(settings, self.owner.identity, router_id)
        envelope = ca_client.lookup_envelope(router_id, settings)
        verified = ca_client._verify_directory_envelope(envelope, settings)
        if _record_compare_fields(record) != _record_compare_fields(verified):
            raise RuntimeError("signed lookup/cache record mismatch")
        self._validate_record(record, fresh=True)
        return record, envelope

    def _validate_record(self, record: dict, fresh: bool):
        now = int(time.time())
        if record.get("status") != "ACTIVE":
            raise ValueError("RDR status is not ACTIVE")
        if not isinstance(record.get("router_id"), str) or not 1 <= len(record["router_id"]) <= 128:
            raise ValueError("RDR router_id invalid")
        if type(record.get("valid_until")) is not int or record["valid_until"] <= now:
            raise ValueError("RDR expired")
        if fresh and record["valid_until"] > now + 30:
            raise ValueError("RDR freshness exceeds 30 seconds")
        if type(record.get("record_seq")) is not int or record["record_seq"] < 1:
            raise ValueError("RDR sequence invalid")
        if not isinstance(record.get("certificate_serial"), str) or not record["certificate_serial"]:
            raise ValueError("RDR certificate serial missing")
        _raw_ed25519(record)
        _rsa_public(record)
        _endpoint_from_record(record)
        if fresh:
            if ca_client.is_revoked(record["certificate_serial"], self._settings()):
                raise ValueError("RDR certificate revoked")

    def _cached_record(self, router_id: str) -> dict:
        record = ca_client.cached_record(router_id, self._settings())
        self._validate_record(record, fresh=False)
        return record

    def _find_peer_record(self, peer) -> dict:
        settings = self._settings()
        cache, bundle = ca_client._load_verified_cache(settings)
        envelopes = list(cache.get("lookups", {}).values())
        if bundle:
            envelopes.extend(bundle.get("records", []))
        target_endpoint = None
        try:
            target_endpoint = _normalized_endpoint(peer.endpoint)
        except Exception:
            pass
        for envelope in envelopes:
            try:
                record = ca_client._verify_directory_envelope(envelope, settings)
                if record.get("router_id") == peer.id:
                    return record
                if target_endpoint:
                    for item in record.get("wan_endpoints", []):
                        if _normalized_endpoint(item) == target_endpoint:
                            return record
            except Exception:
                continue
        # Configured peer IDs are router IDs; no unsigned YAML key is accepted as identity.
        return ca_client.cached_record(peer.id, settings)

    def _policy(self) -> dict:
        cache, payload = ca_client._load_verified_cache(self._settings())
        if payload is None:
            raise RuntimeError("no signed Router-CA policy bundle")
        now = int(time.time())
        if type(payload.get("expires_at")) is not int or payload["expires_at"] <= now:
            raise RuntimeError("signed Router-CA policy bundle expired")
        policy = payload.get("policy")
        if not isinstance(policy, dict):
            raise RuntimeError("signed Router-CA policy missing")
        allowed = policy.get("allowed_suites")
        if not isinstance(allowed, list) or SUITE not in allowed:
            raise RuntimeError("NLS v2 suite is not authorized by Router-CA policy")
        if int(policy.get("minimum_nls_version", 0)) > 2:
            raise RuntimeError("NLS protocol downgrade rejected by Router-CA policy")
        return policy

    def _certificate(self, cert_bytes: bytes, record: dict):
        settings = self._settings()
        root = ca_client._load_root(settings.ca_certificate_file)
        try:
            leaf = x509.load_pem_x509_certificate(cert_bytes)
            now = datetime.now(timezone.utc)
            before = leaf.not_valid_before.replace(tzinfo=timezone.utc)
            after = leaf.not_valid_after.replace(tzinfo=timezone.utc)
            if leaf.issuer != root.subject or not before <= now <= after:
                raise ValueError("certificate issuer or validity mismatch")
            cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(cn) != 1 or cn[0].value != record.get("router_id"):
                raise ValueError("certificate router identity mismatch")
            if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("router certificate is a CA")
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
                raise ValueError("router certificate lacks client-auth EKU")
            if not isinstance(leaf.public_key(), ed25519.Ed25519PublicKey):
                raise ValueError("router certificate key type mismatch")
            cert_key = leaf.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if cert_key != _raw_ed25519(record):
                raise ValueError("certificate/RDR Ed25519 key mismatch")
            if format(leaf.serial_number, "x").lower().removeprefix("0x") != str(record.get("certificate_serial", "")).lower().removeprefix("0x"):
                raise ValueError("certificate/RDR serial mismatch")
            root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                                     padding.PKCS1v15(), leaf.signature_hash_algorithm)
            return leaf
        except Exception as exc:
            raise ValueError("Router-CA certificate validation failed") from exc

    def _self_record(self):
        return self._record_envelope(self.owner.cfg.router_id)

    def _session(self, peer_record, sid, endpoint_value, keys, send_label, recv_label, vip=""):
        from .daemon import Session
        host, port = _normalized_endpoint(endpoint_value)
        peer_id = peer_record["router_id"]
        peer_key = _raw_ed25519(peer_record)
        self.owner.sessions[sid] = Session(
            peer_id, (host, port), sid, keys[send_label], keys[recv_label],
            peer_key, ReplayWindow(self.owner.cfg.replay_window),
            time.time(), time.time(), 0, vip,
        )
        from .config import PeerConfig
        self.owner.peers[peer_id] = PeerConfig(
            peer_id, endpoint_value, base64.b64encode(peer_key).decode("ascii"),
            None, [], peer_record["rsa_encryption_public_key"],
        )
        self.owner.stats["established"] += 1
        self.log.info(json.dumps({
            "event": "nls_handshake_established", "peer": peer_id,
            "session_id": sid.hex(), "state": "ESTABLISHED",
        }, sort_keys=True, separators=(",", ":")))
        self.owner._flush_pending(peer_id)
        for alias, configured in list(self.owner.peers.items()):
            if alias != peer_id and configured.endpoint == endpoint_value:
                self.owner._flush_pending(alias)


    def peer_for_id(self, router_id: str):
        """Build a peer only from a signature-verified Router-CA record."""
        from .config import PeerConfig
        record = self._cached_record(router_id)
        endpoint_value = _endpoint_from_record(record)
        return PeerConfig(
            router_id, endpoint_value,
            base64.b64encode(_raw_ed25519(record)).decode("ascii"),
            None, [], record["rsa_encryption_public_key"],
        )

    def start(self, peer, original_ip: str):
        if self.vip is None:
            try:
                host, _port = _normalized_endpoint(peer.endpoint)
                route = __import__("subprocess").run(
                    ["ip", "-j", "route", "get", host], check=True,
                    capture_output=True, text=True)
                routes = __import__("json").loads(route.stdout)
                interface = routes[0].get("dev") if routes else None
                if not interface:
                    raise RuntimeError("cannot determine WAN interface for vIP")
                self.vip = VIPManager(interface)
                self.vip.cleanup_startup()
            except Exception:
                self._drop("NLS_HS_VIP_INTERFACE_REQUIRED", stage="S2")
                return
        if len(self.pending) >= MAX_PENDING:
            self._drop("NLS_HS_PENDING_LIMIT", stage="S2")
            return
        sid = None
        vip_address = None
        vip_sock = None
        try:
            peer_record = self._find_peer_record(peer)
            peer_id = peer_record["router_id"]
            peer_record, peer_envelope = self._record_envelope(peer_id)
            local_record, local_envelope = self._self_record()
            policy = self._policy()
            self._validate_record(peer_record, fresh=True)
            self._validate_record(local_record, fresh=True)
            vip_address = self.vip.allocate()
            vip_sock = self.vip.bind_socket(vip_address, self.owner.cfg.listen_port)
            vip_sock.setblocking(False)
            sid = os.urandom(16)
            nonce = os.urandom(32)
            identity_raw = self.owner.identity_public.encode("ascii")
            identity_raw = base64.b64decode(identity_raw, validate=True)
            rsa_pem = _rsa_public(local_record).public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            obj = {
                "session_id": sid, "router_id": local_record["router_id"],
                "ed25519_public_key": identity_raw,
                "rsa_encryption_public_key": rsa_pem,
                "nonce_s": nonce, "timestamp": int(time.time()), "vip": vip_address,
                "padding": os.urandom(7600),
            }
            obj = sign_v2(M1, obj, self.owner.identity)
            packet = encode_v2_message(M1, sid, _rsa_public(peer_record), obj)
            host, port = _normalized_endpoint(_endpoint_from_record(peer_record))
            vip_sock.sendto(packet, (host, port))
            self.pending[sid] = {
                "role": "S", "state": "M1_SENT", "created": time.monotonic(),
                "peer_record": peer_record, "peer_envelope": peer_envelope,
                "local_record": local_record, "local_envelope": local_envelope,
                "m1": obj, "m1_plain": __import__("cbor2").dumps(obj, canonical=True),
                "vip": vip_address, "vip_sock": vip_sock, "peer_endpoint": _endpoint_from_record(peer_record),
                "peer_id": peer_id, "nonce_s": nonce,
            }
            self.vip_sockets[sid] = vip_sock
            self.owner.stats["handshakes"] += 1
        except Exception:
            if vip_sock:
                vip_sock.close()
            if vip_address:
                self.vip.release(vip_address)
            self._drop("NLS_HS_START_FAILED", stage="S2")

    def handle_packet(self, packet: bytes, addr, source_socket=None):
        if not self._allow_source(addr):
            self._drop("NLS_HS_RATE_LIMIT", addr, "S2")
            return
        try:
            kind, sid, envelope, _aad = decode_v2_envelope(packet)
            if kind == M1:
                self._handle_m1(packet, addr, sid)
            elif kind == M2:
                self._handle_m2(packet, addr, sid)
            elif kind == M3:
                self._handle_m3(packet, addr, sid)
            elif kind == M4:
                self._handle_m4(packet, addr, sid)
            else:
                self._drop("NLS_HS_OUT_OF_ORDER", addr)
        except Exception:
            self._drop("NLS_HS_MALFORMED", addr)

    def _handle_m1(self, packet, addr, sid):
        if sid in self.seen or sid in self.pending or sid in self.owner.sessions:
            self._drop("NLS_HS_REPLAY", addr, "D:M1")
            return
        if len(self.pending) >= MAX_PENDING:
            self._drop("NLS_HS_PENDING_LIMIT", addr, "D:M1")
            return
        try:
            kind, decoded_sid, obj, m1_plain = open_v2_message(packet, self.owner.encryption_private_key)
            if kind != M1 or decoded_sid != sid:
                raise ValueError("wrong message type")
            verify_timestamp(obj["timestamp"])
            record = self._cached_record(obj["router_id"])
            if obj["ed25519_public_key"] != _raw_ed25519(record):
                raise ValueError("M1 Ed25519 key differs from cached signed RDR")
            if _rsa_public({"rsa_encryption_public_key": obj["rsa_encryption_public_key"].decode("ascii")}).public_numbers() != _rsa_public(record).public_numbers():
                raise ValueError("M1 RSA key differs from cached signed RDR")
            verify_v2_signature(M1, obj, _raw_ed25519(record))
            if str(ipaddress.IPv6Address(addr[0])) != str(ipaddress.IPv6Address(obj["vip"])):
                raise ValueError("M1 vIP differs from observed source")
            self._validate_record(record, fresh=False)
            policy = self._policy()
            local_record, local_envelope = self._self_record()
            local_cert = self._settings().certificate_file.read_bytes()
            self._certificate(local_cert, local_record)
            eph = x25519.X25519PrivateKey.generate()
            nonce_d = os.urandom(32)
            obj2 = {
                "session_id": sid, "router_id": local_record["router_id"],
                "certificate": local_cert, "RDR": local_envelope,
                "gateway_ips": local_record.get("gateway_ips", []),
                "sa_proposals": list(policy["allowed_suites"]),
                "dh_pub_D": eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                "nonce_d": nonce_d,
                "ike_meta": {"version": 2, "nonce_s": obj["nonce_s"]},
                "H1": transcript_h1(m1_plain),
            }
            obj2 = sign_v2(M2, obj2, self.owner.identity)
            packet2 = encode_v2_message(M2, sid, _rsa_public(record), obj2)
            if len(packet2) > len(packet):
                raise ValueError("M2 exceeds received M1 amplification budget")
            self.owner.sock.sendto(packet2, addr)
            self.pending[sid] = {
                "role": "D", "state": "M2_SENT", "created": time.monotonic(),
                "peer_record": record, "local_record": local_record,
                "local_envelope": local_envelope, "m1": obj, "m1_plain": m1_plain,
                "m2": obj2, "m2_plain": __import__("cbor2").dumps(obj2, canonical=True),
                "eph": eph, "source_addr": addr, "vip": obj["vip"],
                "peer_endpoint": _endpoint_from_record(record),
            }
            self.seen[sid] = time.monotonic() + PENDING_REPLAY_TTL
        except Exception:
            self._drop("NLS_HS_M1_REJECTED", addr, "D:M1")

    def _handle_m2(self, packet, addr, sid):
        state = self.pending.get(sid)
        if not state or state.get("role") != "S" or state.get("state") != "M1_SENT":
            self._drop("NLS_HS_OUT_OF_ORDER", addr, "S:M2")
            return
        try:
            kind, decoded_sid, obj, m2_plain = open_v2_message(packet, self.owner.encryption_private_key)
            if kind != M2 or decoded_sid != sid:
                raise ValueError("wrong message type")
            record, envelope = self._record_envelope(state["peer_id"])
            if _record_compare_fields(ca_client._verify_directory_envelope(obj["RDR"], self._settings())) != _record_compare_fields(record):
                raise ValueError("M2 RDR differs from fresh S3 lookup")
            self._validate_record(record, fresh=True)
            self._certificate(obj["certificate"], record)
            verify_v2_signature(M2, obj, _raw_ed25519(record))
            if obj["H1"] != transcript_h1(state["m1_plain"]):
                raise ValueError("M2 H1 transcript mismatch")
            if obj["sa_proposals"] != self._policy()["allowed_suites"] or SUITE not in obj["sa_proposals"]:
                raise ValueError("SA downgrade or proposal mismatch")
            expected_endpoint = _normalized_endpoint(_endpoint_from_record(record))
            if (str(ipaddress.ip_address(addr[0])), int(addr[1])) != expected_endpoint:
                raise ValueError("M2 source endpoint mismatch")
            if _normalized_endpoint(state["peer_endpoint"]) != expected_endpoint:
                raise ValueError("peer endpoint changed")
            eph = x25519.X25519PrivateKey.generate()
            local_record, local_envelope = self._record_envelope(self.owner.cfg.router_id)
            local_cert = self._settings().certificate_file.read_bytes()
            self._certificate(local_cert, local_record)
            h2 = transcript_h2(state["m1_plain"], m2_plain)
            obj3 = {
                "session_id": sid, "certificate": local_cert, "RDR": local_envelope,
                "dh_pub_S": eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                "chosen_sa": SUITE, "S.wan_endpoint": _endpoint_from_record(local_record),
                "H2": h2,
            }
            obj3 = sign_v2(M3, obj3, self.owner.identity)
            packet3 = encode_v2_message(M3, sid, _rsa_public(record), obj3)
            state.update({"state": "M3_SENT", "peer_record": record, "peer_envelope": envelope,
                          "local_record": local_record, "local_envelope": local_envelope,
                          "m2": obj, "m2_plain": m2_plain, "m3": obj3,
                          "m3_plain": __import__("cbor2").dumps(obj3, canonical=True), "eph": eph})
            state["vip_sock"].sendto(packet3, _normalized_endpoint(_endpoint_from_record(record)))
        except Exception:
            self._abort(sid, "NLS_HS_S3_REJECTED", addr)

    def _handle_m3(self, packet, addr, sid):
        state = self.pending.get(sid)
        if not state or state.get("role") != "D" or state.get("state") != "M2_SENT":
            self._drop("NLS_HS_OUT_OF_ORDER", addr, "D:M3")
            return
        try:
            if str(ipaddress.IPv6Address(addr[0])) != str(ipaddress.IPv6Address(state["vip"])):
                raise ValueError("M3 did not arrive from bootstrap vIP")
            kind, decoded_sid, obj, m3_plain = open_v2_message(packet, self.owner.encryption_private_key)
            if kind != M3 or decoded_sid != sid:
                raise ValueError("wrong message type")
            fresh, envelope = self._record_envelope(state["m1"]["router_id"])
            embedded = ca_client._verify_directory_envelope(obj["RDR"], self._settings())
            if _record_compare_fields(embedded) != _record_compare_fields(fresh):
                raise ValueError("M3 RDR differs from fresh S4 lookup")
            if obj["S.wan_endpoint"] not in fresh.get("wan_endpoints", []):
                raise ValueError("M3 WAN endpoint is not CA-authorized")
            if obj["chosen_sa"] != SUITE or obj["chosen_sa"] not in self._policy()["allowed_suites"]:
                raise ValueError("SA downgrade rejected")
            if obj["H2"] != transcript_h2(state["m1_plain"], state["m2_plain"]):
                raise ValueError("M3 H2 transcript mismatch")
            self._certificate(obj["certificate"], fresh)
            verify_v2_signature(M3, obj, _raw_ed25519(fresh))
            h3 = transcript_h3(state["m1_plain"], state["m2_plain"], m3_plain)
            keys = derive_session_keys(state["eph"], obj["dh_pub_S"], h3, sid)
            local_record, local_envelope = self._self_record()
            local_cert = self._settings().certificate_file.read_bytes()
            self._certificate(local_cert, local_record)
            obj4 = {
                "session_id": sid, "trust": True, "H3": h3,
                "confirm": __import__("nls.key_schedule", fromlist=["confirmation_mac"]).confirmation_mac(keys["k_confirm"], h3),
            }
            obj4 = sign_v2(M4, obj4, self.owner.identity)
            packet4 = encode_v2_message(M4, sid, _rsa_public(fresh), obj4)
            # M4 is the final bootstrap response; it is sent to the vIP source.
            self.owner.sock.sendto(packet4, state["source_addr"])
            self._session(fresh, sid, obj["S.wan_endpoint"], keys,
                          "d_to_s_key", "s_to_d_key", obj["vip"] if "vip" in obj else state["vip"])
            self.pending.pop(sid, None)
        except Exception:
            self._abort(sid, "NLS_HS_S4_REJECTED", addr)

    def _handle_m4(self, packet, addr, sid):
        state = self.pending.get(sid)
        if not state or state.get("role") != "S" or state.get("state") != "M3_SENT":
            self._drop("NLS_HS_OUT_OF_ORDER", addr, "S:M4")
            return
        try:
            kind, decoded_sid, obj, _m4_plain = open_v2_message(packet, self.owner.encryption_private_key)
            if kind != M4 or decoded_sid != sid:
                raise ValueError("wrong message type")
            record = state["peer_record"]
            if (str(ipaddress.ip_address(addr[0])), int(addr[1])) != _normalized_endpoint(_endpoint_from_record(record)):
                raise ValueError("M4 source endpoint mismatch")
            verify_v2_signature(M4, obj, _raw_ed25519(record))
            expected_h3 = transcript_h3(state["m1_plain"], state["m2_plain"], state["m3_plain"])
            if obj["H3"] != expected_h3:
                raise ValueError("M4 H3 transcript mismatch")
            keys = derive_session_keys(state["eph"], state["m2"]["dh_pub_D"], expected_h3, sid)
            verify_confirmation(keys["k_confirm"], expected_h3, obj["confirm"])
            if obj["trust"] is not True:
                raise ValueError("M4 trust flag false")
            self._session(record, sid, _endpoint_from_record(record), keys,
                          "s_to_d_key", "d_to_s_key")
            vip = state["vip"]
            sock = state["vip_sock"]
            sock.close()
            self.vip_sockets.pop(sid, None)
            self.vip.release(vip)
            self.pending.pop(sid, None)
        except Exception:
            self._abort(sid, "NLS_HS_M4_REJECTED", addr)

    def _abort(self, sid: bytes, reason: str, addr=None):
        state = self.pending.pop(sid, None)
        if state and state.get("role") == "S":
            vip = state.get("vip")
            sock = state.get("vip_sock")
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
            self.vip_sockets.pop(sid, None)
            if vip and self.vip:
                self.vip.release(vip)
        self._drop(reason, addr, state.get("state", "unknown") if state else "unknown")

    def expire(self, now=None):
        current = time.monotonic() if now is None else now
        for sid, state in list(self.pending.items()):
            if current - state["created"] >= HANDSHAKE_TIMEOUT:
                self._abort(sid, "NLS_HS_TIMEOUT")
        for sid, expires in list(self.seen.items()):
            if expires <= current:
                self.seen.pop(sid, None)
        if self.vip:
            for address in self.vip.expire(current):
                for sid, state in list(self.pending.items()):
                    if state.get("vip") == address:
                        self._abort(sid, "NLS_HS_VIP_TTL_EXPIRED")

    def startup_cleanup(self):
        if self.vip:
            self.vip.cleanup_startup()

    def close(self):
        for sid in list(self.pending):
            self._abort(sid, "NLS_HS_SHUTDOWN")
        if self.vip:
            self.vip.release_all()
