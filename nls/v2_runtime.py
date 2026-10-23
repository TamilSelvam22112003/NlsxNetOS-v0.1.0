"""NLH2 M1-M4 handshake runtime used by NLSDaemon.

This module deliberately fails closed if a live signed Router-CA lookup,
certificate validation, policy check, or endpoint cross-check cannot complete.
The active data plane is NLE2 with directional session keys and AES-256-GCM;
RSA is retained only for the handshake envelope where required.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import threading
import ipaddress
import logging
import json
import os
import time
import traceback
from functools import lru_cache
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import ca_client
from .handshake import (
    M1, M2, M3, M4, decode_v2_envelope, encode_v2_message,
    open_v2_message, sign_v2, transcript_h1, transcript_h2, transcript_h3,
    verify_timestamp, verify_v2_signature, verify_confirmation,
)
from .key_schedule import derive_session_keys
from .replay import ReplayWindow
from .vip import DEFAULT_POOL, DEFAULT_STATE as VIP_STATE_PATH, VIPManager
from .vip_table import VIPVerificationTable
from .source_token import derive_source_token, open_source_token_socket


SUITE = "X25519-HKDF-SHA256-AES-256-GCM-Ed25519-RSA-OAEP-SHA256"
MAX_PENDING = 64
HANDSHAKE_TIMEOUT = 5
PENDING_REPLAY_TTL = 300
M2_MAX_DATAGRAM = 8500


class RDRFieldError(ValueError):
    """Safe field-level validation failure; never stores the offending value."""

    def __init__(self, field_name: str, cause_type: str):
        self.field_name = field_name
        self.cause_type = cause_type
        super().__init__(f"RDR field {field_name} invalid ({cause_type})")


def _validate_rdr_field(record: dict, field_name: str, validator) -> None:
    try:
        validator(record)
    except Exception as exc:
        cause_type = f"{type(exc).__module__}.{type(exc).__name__}"
        raise RDRFieldError(field_name, cause_type) from exc


@lru_cache(maxsize=512)
def _cached_ed25519_public(value: str) -> bytes:
    raw = base64.b64decode(value.encode("ascii"), validate=True)
    if len(raw) != 32:
        raise ValueError("RDR Ed25519 key length invalid")
    return raw


def _raw_ed25519(record: dict) -> bytes:
    field_name = "ed25519_public_key"
    value = record.get(field_name)
    try:
        if not isinstance(value, str):
            raise TypeError("expected base64-encoded text")
        return _cached_ed25519_public(value)
    except Exception as exc:
        raise RDRFieldError(
            field_name, f"{type(exc).__module__}.{type(exc).__name__}"
        ) from exc


@lru_cache(maxsize=512)
def _cached_rsa_public(value: str):
    key = serialization.load_pem_public_key(value.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072:
        raise ValueError("RDR RSA key must be RSA-3072")
    return key


def _rsa_public(record: dict):
    field_name = "rsa_encryption_public_key"
    value = record.get(field_name)
    try:
        if not isinstance(value, str):
            raise TypeError("expected PEM-encoded text")
        return _cached_rsa_public(value)
    except Exception as exc:
        raise RDRFieldError(
            field_name, f"{type(exc).__module__}.{type(exc).__name__}"
        ) from exc


class RecordFieldError(ValueError):
    """Identify a malformed signed RDR field without exposing its contents."""

    def __init__(self, field: str, cause: Exception):
        self.field_name = field
        self.cause_type = f"{type(cause).__module__}.{type(cause).__name__}"
        super().__init__(f"invalid Router-CA record field {field} ({self.cause_type})")


def _safe_start_error_code(exc: Exception) -> str:
    """Map known static failures to safe diagnostic codes; never log exception text."""
    if getattr(exc, "field_name", None):
        return "RDR_FIELD_INVALID"
    message = str(exc)
    known = (
        ("signed lookup/cache record mismatch", "LOOKUP_CACHE_RECORD_MISMATCH"),
        ("Router-CA lookup response nonce/type mismatch", "LOOKUP_NONCE_TYPE_MISMATCH"),
        ("Router-CA directory lookup rate limited", "LOOKUP_RATE_LIMITED"),
        ("Router-CA directory lookup not authorized", "LOOKUP_NOT_AUTHORIZED"),
        ("Router-CA lookup request rejected", "LOOKUP_REQUEST_REJECTED"),
        ("Router-CA lookup nonce is not bound to the signed record", "LOOKUP_NONCE_BINDING_MISMATCH"),
        ("Router-CA lookup response freshness invalid", "LOOKUP_FRESHNESS_INVALID"),
        ("Router-CA lookup record rollback rejected", "LOOKUP_ROLLBACK_REJECTED"),
        ("Router-CA directory freshness expired", "DIRECTORY_FRESHNESS_EXPIRED"),
        ("no verified Router-CA directory bundle", "DIRECTORY_CACHE_UNAVAILABLE"),
        ("Router-CA directory signature verification failed", "DIRECTORY_SIGNATURE_INVALID"),
    )
    for fragment, code in known:
        if fragment in message:
            return code
    return "UNCLASSIFIED_START_FAILURE"


def _endpoint_from_record(record: dict) -> str:
    endpoints = record.get("wan_endpoints")
    if not isinstance(endpoints, list) or not endpoints or not all(isinstance(x, str) for x in endpoints):
        raise ValueError("RDR WAN endpoint missing")
    return endpoints[0]


def _normalized_endpoint(value: str):
    from .config import endpoint
    host, port = endpoint(value)
    return str(ipaddress.ip_address(host)), port


# Master-spec S3/S4 equality contract: stable identity/authorization fields only.
# status is checked independently (the fresh RDR must be ACTIVE); record_seq is
# a monotonic freshness value enforced by ca_client, not an equality field, because
# a newer signed lookup may legitimately advance it. issued_at/valid_until are
# per-lookup freshness metadata and are validated separately.
RDR_S3_S4_COMPARE_FIELDS = (
    "router_id",
    "ed25519_public_key",
    "rsa_encryption_public_key",
    "wan_endpoints",
    "gateway_ips",
    "prefixes",
    "certificate_serial",
)


def _record_compare_fields(record: dict) -> dict:
    return {field: record.get(field) for field in RDR_S3_S4_COMPARE_FIELDS}


class HandshakeV2:
    def __init__(self, owner):
        self.owner = owner
        self.log = logging.getLogger("nlsxnetos.nls")
        self.pending: dict[bytes, dict] = {}
        self.seen: dict[bytes, float] = {}
        # Independent, bounded pre-decryption controls. These are resource
        # limits, not identity or authorization decisions.
        self.buckets: dict[str, tuple[float, float]] = {}
        self.prefix_buckets: dict[str, tuple[float, float]] = {}
        self.interface_buckets: dict[str, tuple[float, float]] = {}
        self.global_bucket = (500.0, time.monotonic())
        self._bucket_cleanup_at = 0.0
        self.vip_sockets: dict[bytes, object] = {}
        self.retired_vips: dict[str, float] = {}
        # This table contains only short-lived candidate identity rows; it is not
        # consulted for routing until the exact CA/peer checks below succeed.
        self.vip_verification = VIPVerificationTable(router_id=owner.cfg.router_id)
        self.settings = None
        self.vip = None
        if owner.cfg.bind_interface:
            self.vip = VIPManager(owner.cfg.bind_interface)

    def sockets(self):
        return list(self.vip_sockets.values())

    def is_retired_vip(self, address: str) -> bool:
        try:
            normalized = str(ipaddress.IPv6Address(address))
        except ValueError:
            return False
        expiry = self.retired_vips.get(normalized, 0.0)
        if expiry <= time.monotonic():
            self.retired_vips.pop(normalized, None)
            return False
        return True

    def _settings(self):
        if self.settings is None:
            path = os.environ.get("NLS_ROUTER_CA_CONFIG") or os.environ.get("NLSXNETOS_ROUTER_CA_CLIENT_CONFIG", "/etc/nlsxnetos/router-ca-client.yaml")
            try:
                settings = ca_client.ClientSettings.load(path)
            except binascii.Error as exc:
                # ClientSettings.load strictly decodes the pinned CA Ed25519 key.
                # Report the field identifier and exception class only; never log
                # the configured key or any other secret/configuration value.
                raise RecordFieldError(
                    "router_ca_client_config.server_public_key", exc
                ) from exc
            if settings.router_id != self.owner.cfg.router_id:
                raise RuntimeError("Router-CA client router_id does not match NLS router_id")
            self.settings = settings
        return self.settings

    def _drop(self, reason: str, addr=None, stage="unknown", error_type=None,
              error_field=None, error_stage=None, error_errno=None, error_code=None):
        self.owner.stats["drops"] += 1
        counters = getattr(self.owner, "reason_counters", None)
        if isinstance(counters, dict):
            counters[reason] = counters.get(reason, 0) + 1
        source = str(addr[0]) if isinstance(addr, tuple) and addr else "unknown"
        # Do not include raw packets, keys, certificates, tokens, plaintext, or exceptions.
        event = {
            "event": "nls_drop", "reason": reason, "stage": stage,
            "source": source, "time": int(time.time()),
        }
        if error_type:
            event["error_type"] = str(error_type)
        if error_field:
            event["error_field"] = str(error_field)
        if error_stage:
            event["error_stage"] = str(error_stage)
        if error_errno is not None:
            event["error_errno"] = int(error_errno)
        if error_code:
            event["error_code"] = str(error_code)
        self.log.warning(json.dumps(event, sort_keys=True, separators=(",", ":")))

    @staticmethod
    def _consume_bucket(table, key, capacity, refill_per_second, now):
        tokens, last = table.get(key, (float(capacity), now))
        tokens = min(float(capacity), tokens + max(0.0, now - last) * refill_per_second)
        if tokens < 1.0:
            table[key] = (tokens, now)
            return False
        table[key] = (tokens - 1.0, now)
        return True

    def _prune_buckets(self, now):
        if now < getattr(self, "_bucket_cleanup_at", 0.0):
            return
        self._bucket_cleanup_at = now + 30.0
        for table in (
            self.buckets, self.prefix_buckets, self.interface_buckets,
        ):
            for key, (_tokens, last) in list(table.items()):
                if now - last > 300.0:
                    table.pop(key, None)
            # Keep attacker-controlled keys bounded even under source rotation.
            while len(table) > 4096:
                oldest = min(table, key=lambda item: table[item][1])
                table.pop(oldest, None)

    def _allow_source(self, addr, ingress_interface=None) -> bool:
        try:
            source_ip = ipaddress.ip_address(addr[0])
        except (ValueError, TypeError, IndexError):
            return False
        source = str(source_ip)
        now = time.monotonic()
        self._prune_buckets(now)

        # Global limiter remains effective when attackers rotate source addresses.
        tokens, last = getattr(self, "global_bucket", (500.0, now))
        tokens = min(500.0, tokens + max(0.0, now - last) * 100.0)
        if tokens < 1.0:
            self.global_bucket = (tokens, now)
            return False
        self.global_bucket = (tokens - 1.0, now)

        # The receive loop supplies the kernel-reported ingress interface index.
        # Explicit SO_BINDTODEVICE configurations are a safe fallback.
        interface = ingress_interface or getattr(self.owner.cfg, "bind_interface", "") or "unknown-ingress"
        if not self._consume_bucket(self.interface_buckets, str(interface), 300, 50.0, now):
            return False

        prefix = str(ipaddress.ip_network(
            f"{source_ip}/{64 if source_ip.version == 6 else 24}", strict=False
        ))
        if not self._consume_bucket(self.prefix_buckets, prefix, 40, 8.0, now):
            return False

        # Preserve the previous exact-source protection as an additional layer.
        return self._consume_bucket(self.buckets, source, 10, 2.0, now)

    def _record_envelope(self, router_id: str) -> tuple[dict, dict]:
        settings = self._settings()
        # Keep the payload and signed envelope from the same nonce-bound lookup.
        # Re-reading the shared cache here can race with the CA sync agent and pair
        # a valid response with a newer envelope for the same router ID.
        record, envelope = ca_client.lookup(
            settings, self.owner.identity, router_id, include_envelope=True
        )
        verified = ca_client._verify_directory_envelope(envelope, settings)
        if _record_compare_fields(record) != _record_compare_fields(verified):
            raise RuntimeError("signed lookup/response record mismatch")
        self._validate_record(record, fresh=True)
        return record, envelope

    def compare_fresh_record(self, embedded: dict, fresh: dict, stage: str) -> None:
        if stage not in ("S3", "S4"):
            raise ValueError("NLS_HS_STAGE_INVALID")
        if _record_compare_fields(embedded) != _record_compare_fields(fresh):
            raise ValueError(f"NLS_HS_CA_MISMATCH_{stage}")

    def validate_suite(self, chosen: str, proposals: list, policy: dict) -> None:
        allowed = policy.get("allowed_suites")
        if not isinstance(allowed, list) or chosen != SUITE or chosen not in allowed:
            raise ValueError("NLS_HS_SA_DOWNGRADE")
        if not isinstance(proposals, list) or proposals != allowed:
            raise ValueError("NLS_HS_SA_PROPOSAL_MISMATCH")

    @staticmethod
    def _certificate_der(certificate_bytes: bytes) -> bytes:
        """Normalize the configured/presented certificate to DER for exact matching."""
        raw = bytes(certificate_bytes)
        try:
            return x509.load_pem_x509_certificate(raw).public_bytes(serialization.Encoding.DER)
        except ValueError:
            return x509.load_der_x509_certificate(raw).public_bytes(serialization.Encoding.DER)

    def _validate_record(self, record: dict, fresh: bool):
        now = int(time.time())
        if record.get("status") != "ACTIVE":
            raise ValueError("RDR status is not ACTIVE")
        if not isinstance(record.get("router_id"), str) or not 1 <= len(record["router_id"]) <= 128:
            raise ValueError("RDR router_id invalid")
        if type(record.get("valid_until")) is not int or record["valid_until"] <= now:
            raise ValueError("RDR expired")
        if fresh:
            issued_at = record.get("issued_at")
            valid_until = record["valid_until"]
            if type(issued_at) is not int or issued_at > now or now - issued_at > 30:
                raise ValueError("RDR issued_at is missing, future-dated, or older than 30 seconds")
            if valid_until > now + 30 or valid_until <= issued_at:
                raise ValueError("RDR freshness interval is invalid or exceeds 30 seconds")
        if type(record.get("record_seq")) is not int or record["record_seq"] < 1:
            raise ValueError("RDR sequence invalid")
        if not isinstance(record.get("certificate_serial"), str) or not record["certificate_serial"]:
            raise ValueError("RDR certificate serial missing")
        _validate_rdr_field(record, "ed25519_public_key", _raw_ed25519)
        _validate_rdr_field(record, "rsa_encryption_public_key", _rsa_public)
        _validate_rdr_field(record, "wan_endpoints", _endpoint_from_record)
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
            # Newer cryptography releases expose timezone-aware UTC properties.
            # Keep compatibility with older distro packages without triggering
            # deprecation warnings on current runners.
            before = getattr(leaf, "not_valid_before_utc", None)
            after = getattr(leaf, "not_valid_after_utc", None)
            if before is None:
                before = leaf.not_valid_before.replace(tzinfo=timezone.utc)
            if after is None:
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

    def _session(
        self, peer_record, sid, endpoint_value, keys, send_label, recv_label,
        vip="", local_record=None, source_token_context=None, activate=True,
    ):
        from .daemon import Session
        local_record = dict(local_record or {})
        if not local_record.get("originalIP") or not peer_record.get("originalIP"):
            raise ValueError("SourceToken requires authoritative local and peer originalIP values")
        if not isinstance(source_token_context, dict):
            raise ValueError("SourceToken handshake context missing")
        role = source_token_context.get("role")
        if role not in ("S", "D"):
            raise ValueError("invalid SourceToken handshake role")
        h3 = source_token_context.get("h3")
        nonce_s = source_token_context.get("nonce_s")
        nonce_d = source_token_context.get("nonce_d")
        if not isinstance(h3, bytes) or len(h3) != 32:
            raise ValueError("SourceToken H3 must be 32 bytes")
        if not isinstance(nonce_s, bytes) or len(nonce_s) != 32:
            raise ValueError("SourceToken nonce_s must be 32 bytes")
        if not isinstance(nonce_d, bytes) or len(nonce_d) != 32:
            raise ValueError("SourceToken nonce_d must be 32 bytes")
        session_secret = keys.get("session_secret")
        if not isinstance(session_secret, bytes) or len(session_secret) != 32:
            raise ValueError("SourceToken session secret missing")
        source_salt = hashlib.sha256(h3 + nonce_s + nonce_d).digest()
        local_direction, peer_direction = (
            ("A-to-B", "B-to-A") if role == "S" else ("B-to-A", "A-to-B")
        )
        send_token = str(derive_source_token(
            session_secret, source_salt, local_record["originalIP"],
            peer_record["originalIP"], vip, local_direction,
        ))
        recv_token = str(derive_source_token(
            session_secret, source_salt, peer_record["originalIP"],
            local_record["originalIP"], vip, peer_direction,
        ))
        if send_token == recv_token:
            raise ValueError("SourceToken direction collision")
        if not hasattr(self.owner, "source_token_lock"):
            self.owner.source_token_lock = threading.RLock()
        if not hasattr(self.owner, "source_token_reserved"):
            self.owner.source_token_reserved = set()
        if not hasattr(self.owner, "source_token_sessions"):
            self.owner.source_token_sessions = {}
        with self.owner.source_token_lock:
            if send_token in self.owner.source_token_reserved or recv_token in self.owner.source_token_reserved:
                raise ValueError("SourceToken local active/pending collision")
            self.owner.source_token_reserved.update((send_token, recv_token))

        lease = None
        try:
            host, port = _normalized_endpoint(endpoint_value)
            local_endpoint = _endpoint_from_record(local_record)
            _local_host, local_port = _normalized_endpoint(local_endpoint)
            interface = getattr(self.owner.cfg, "bind_interface", "") or None
            lease = open_source_token_socket(
                send_token, peer_record["originalIP"], local_port, interface=interface,
            )
            peer_id = peer_record["router_id"]
            peer_key = _raw_ed25519(peer_record)
            send_iv_label = send_label.removesuffix("_key") + "_iv_prefix"
            recv_iv_label = recv_label.removesuffix("_key") + "_iv_prefix"
            now_wall = time.time()
            session = Session(
                peer_id, (host, port), sid, bytearray(keys[send_label]), bytearray(keys[recv_label]),
                peer_key, keys[send_iv_label], keys[recv_iv_label],
                ReplayWindow(self.owner.cfg.replay_window),
                now_wall, now_wall, 0, vip,
            )
            session.peer_certificate_serial = str(peer_record.get("certificate_serial", ""))
            session.peer_record_seq = int(peer_record.get("record_seq", 0))
            session.peer_record = dict(peer_record)
            session.local_record = local_record
            session.send_token = send_token
            session.recv_token = recv_token
            session.token_lease = lease
            if activate:
                self._activate_session(session)
            return session
        except Exception:
            lease_closed = True
            if lease is not None:
                try:
                    lease.close()
                except Exception:
                    lease_closed = False
            if lease_closed:
                with self.owner.source_token_lock:
                    self.owner.source_token_reserved.discard(send_token)
                    self.owner.source_token_reserved.discard(recv_token)
            raise

    def _activate_session(self, session, flush_pending=True):
        sid = session.session_id
        if not self.vip_verification.is_verified(sid):
            raise RuntimeError("NLS_VIP_IDENTITY_NOT_VERIFIED")
        from .config import PeerConfig
        endpoint_value = f"[{session.endpoint[0]}]:{session.endpoint[1]}"
        peer_config = PeerConfig(
            session.peer_id, endpoint_value,
            base64.b64encode(session.peer_identity).decode("ascii"),
            None, [],
            base64.b64encode(_rsa_public(session.peer_record).public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )).decode("ascii"),
        )
        with self.owner.source_token_lock:
            if session.recv_token in self.owner.source_token_sessions:
                raise ValueError("SourceToken local active/pending collision")
            self.owner.source_token_sessions[session.recv_token] = sid
        # Publish the authenticated original-IP binding only after the full
        # M1-M4 transcript, certificates, RDRs, and key confirmation are accepted.
        # This table is LSDB metadata only; it never installs kernel routes.
        from . import lsdb
        local_record = dict(session.local_record)
        peer_record = dict(session.peer_record)
        peer_original_ip = peer_record.get("originalIP")
        peer_identity = base64.b64encode(session.peer_identity).decode("ascii")
        # Do not publish original-IP reachability until the handshake has
        # authenticated both RDRs and M4 key confirmation has succeeded.
        expiry = time.time() + max(1, int(self.owner.cfg.session_timeout_seconds))
        try:
            lsdb.publish_authenticated_vip(
                session.recv_token,
                session.peer_id,
                peer_original_ip,
                peer_identity,
                source_token=session.recv_token,
                session_id=sid,
                record_seq=int(session.peer_record_seq),
                expires_at=expiry,
                send_token=session.send_token,
                local_original_ip=local_record.get("originalIP"),
            )
            # The local row is an explicit local-direction record; it allows
            # inspection by local originalIP without treating it as a peer.
            lsdb.publish_authenticated_vip(
                session.send_token,
                local_record.get("router_id", self.owner.cfg.router_id),
                local_record.get("originalIP"),
                self.owner.identity_public,
                source_token=session.send_token,
                session_id=sid,
                record_seq=int(local_record.get("record_seq", 0)),
                expires_at=expiry,
                send_token=session.send_token,
                local_original_ip=local_record.get("originalIP"),
            )
        except Exception:
            # Do not partially accept a session when its LSDB publication
            # fails. Undo any entry written by this attempted activation.
            lsdb.remove(session.recv_token, session_id=sid)
            lsdb.remove(session.send_token, session_id=sid)
            with self.owner.source_token_lock:
                if self.owner.source_token_sessions.get(session.recv_token) == sid:
                    self.owner.source_token_sessions.pop(session.recv_token, None)
            raise
        self.owner._mark_sessions_for_overlap(session.peer_id, sid, time.monotonic())
        self.owner.sessions[sid] = session
        # Once the authenticated LSDB rows are committed, discard the short-lived
        # certificate-bearing staging row. It must not persist as routing state.
        self.vip_verification.remove(sid)
        self.owner.peers[session.peer_id] = peer_config
        self.owner.stats["established"] += 1
        self.log.info(json.dumps({
            "event": "nls_handshake_established", "peer": session.peer_id,
            "session_id": sid.hex(), "state": "ESTABLISHED",
            "lsdb_published": True,
        }, sort_keys=True, separators=(",", ":")))
        if flush_pending:
            self.owner._flush_pending(session.peer_id)
            for alias, configured in list(self.owner.peers.items()):
                if alias != session.peer_id and configured.endpoint == endpoint_value:
                    self.owner._flush_pending(alias)

    def _discard_prepared_session(self, session):
        if session is None:
            return
        lease = getattr(session, "token_lease", None)
        closed = True
        try:
            if lease is not None:
                lease.close()
        except Exception:
            closed = False
        if closed:
            with self.owner.source_token_lock:
                self.owner.source_token_reserved.discard(getattr(session, "send_token", ""))
                self.owner.source_token_reserved.discard(getattr(session, "recv_token", ""))

    def peer_for_id(self, router_id: str):
        """Build a peer only from a signature-verified Router-CA record."""
        from .config import PeerConfig
        record = self._cached_record(router_id)
        try:
            endpoint_value = _endpoint_from_record(record)
        except Exception as exc:
            raise RecordFieldError("wan_endpoints", exc) from exc
        try:
            ed25519_public = _raw_ed25519(record)
        except Exception as exc:
            raise RecordFieldError("ed25519_public_key", exc) from exc
        try:
            rsa_public = _rsa_public(record)
        except Exception as exc:
            raise RecordFieldError("rsa_encryption_public_key", exc) from exc
        return PeerConfig(
            router_id, endpoint_value,
            base64.b64encode(ed25519_public).decode("ascii"),
            None, [], base64.b64encode(rsa_public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode("ascii"),
        )

    def start(self, peer, original_ip: str, rekey: bool = False):
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
        if rekey and any(state.get("rekey") and state.get("peer_id") == peer.id for state in self.pending.values()):
            return
        if len(self.pending) >= MAX_PENDING:
            self._drop("NLS_HS_PENDING_LIMIT", stage="S2")
            return
        sid = None
        vip_address = None
        vip_sock = None
        failure_stage = "peer-record-cache"
        try:
            settings = self._settings()
            ca_client.assert_heartbeat_freshness(settings)
            peer_record = self._find_peer_record(peer)
            peer_id = peer_record["router_id"]
            failure_stage = "live-record-envelope"
            peer_record, peer_envelope = self._record_envelope(peer_id)
            failure_stage = "local-record"
            local_record, local_envelope = self._self_record()
            failure_stage = "directory-policy"
            self._policy()
            failure_stage = "record-validation"
            self._validate_record(peer_record, fresh=True)
            self._validate_record(local_record, fresh=True)
            failure_stage = "vip-allocation"
            vip_address = self.vip.allocate()
            failure_stage = "vip-bind"
            vip_sock = self.vip.bind_socket(vip_address, self.owner.cfg.listen_port)
            vip_sock.setblocking(False)
            sid = os.urandom(16)
            # Reserve the short-lived bootstrap vIP in the control-plane table
            # before it can be advertised in M1. It remains unauthenticated and
            # cannot be used to publish router reachability.
            from . import lsdb
            failure_stage = "vip-verification-stage"
            local_certificate_der = self._certificate_der(
                self._settings().certificate_file.read_bytes()
            )
            local_public_key_der = ed25519.Ed25519PublicKey.from_public_bytes(
                self.owner.identity_raw
            ).public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self.vip_verification.stage(
                vip=vip_address,
                router_id=local_record["router_id"],
                original_ip=local_record["originalIP"],
                certificate_der=local_certificate_der,
                public_key_der=local_public_key_der,
                record_seq=int(local_record.get("record_seq", 0)),
                session_id=sid,
                status=local_record.get("status", ""),
                expires_at=time.time() + min(10, int(self.vip.ttl)),
            )
            failure_stage = "vip-table-reservation"
            lsdb.publish_bootstrap_vip(
                vip_address, local_record["router_id"], local_record["originalIP"],
                base64.b64encode(self.owner.identity_raw).decode("ascii"),
                session_id=sid,
                expires_at=time.time() + min(10, int(self.vip.ttl)),
                record_seq=int(local_record.get("record_seq", 0)),
            )
            nonce = os.urandom(32)
            failure_stage = "identity-key-decode"
            identity_raw = self.owner.identity_public.encode("ascii")
            identity_raw = base64.b64decode(identity_raw, validate=True)
            failure_stage = "M1-encode"
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
            if os.environ.get("NLS_HS_DIAGNOSTICS") == "1":
                self.log.info(
                    "NLS_HS_DATAGRAM_SIZE kind=M1 bytes=%d padding_bytes=%d ipv6_minimum_mtu=1280",
                    len(packet), len(obj["padding"]),
                )
            host, port = _normalized_endpoint(_endpoint_from_record(peer_record))
            failure_stage = "M1-send"
            vip_sock.sendto(packet, (host, port))
            self.pending[sid] = {
                "role": "S", "state": "M1_SENT", "created": time.monotonic(),
                "peer_record": peer_record, "peer_envelope": peer_envelope,
                "local_record": local_record, "local_envelope": local_envelope,
                "m1": obj, "m1_plain": __import__("cbor2").dumps(obj, canonical=True),
                "vip": vip_address, "vip_sock": vip_sock, "peer_endpoint": _endpoint_from_record(peer_record),
                "peer_id": peer_id, "nonce_s": nonce, "rekey": bool(rekey),
            }
            self.vip_sockets[sid] = vip_sock
            self.owner.stats["handshakes"] += 1
        except Exception as exc:
            if sid is not None:
                try:
                    self.vip_verification.remove(sid)
                except Exception:
                    self._drop("NLS_VIP_VERIFICATION_CLEANUP_FAILED", stage=failure_stage)
            if failure_stage == "live-record-envelope" and os.environ.get("NLS_HS_DIAGNOSTICS") == "1":
                # Opt-in diagnostics only; off by default.
                self.log.warning(
                    "NLS_HS_START_TRACEBACK stage=%s exception_type=%s frames=%s",
                    failure_stage, type(exc).__name__,
                    "".join(traceback.format_tb(exc.__traceback__)),
                )
            if vip_sock:
                vip_sock.close()
            if vip_address:
                try:
                    self.vip.release(vip_address)
                except Exception as cleanup_exc:
                    self._drop(
                        "NLS_VIP_CLEANUP_FAILED", stage="S2",
                        error_type=type(cleanup_exc).__name__,
                    )
                try:
                    from . import lsdb
                    if sid is not None:
                        lsdb.remove(vip_address, session_id=sid)
                except Exception as cleanup_exc:
                    self._drop(
                        "NLS_VIP_TABLE_CLEANUP_FAILED", stage="S2",
                        error_type=type(cleanup_exc).__name__,
                    )
            message = str(exc).lower()
            freshness_lost = (
                "heartbeat freshness lost" in message or
                (failure_stage == "directory-policy" and any(
                    marker in message for marker in (
                        "expired", "freshness", "rollback mark",
                        "fresh live sync required", "no signed router-ca policy bundle",
                    )
                ))
            )
            self._drop(
                "NLS_CA_FRESHNESS_LOST" if freshness_lost else "NLS_HS_START_FAILED",
                stage="S2",
                error_type=getattr(exc, "cause_type", type(exc).__name__),
                error_field=getattr(exc, "field_name", None),
                error_stage=failure_stage,
                error_errno=getattr(exc, "errno", None),
                error_code="DIRECTORY_FRESHNESS_LOST" if freshness_lost else _safe_start_error_code(exc),
            )

    def handle_packet(self, packet: bytes, addr, source_socket=None):
        if not self._allow_source(addr):
            self._drop("NLS_HS_RATE_LIMIT", addr, "S2")
            return
        if self.is_retired_vip(str(addr[0])):
            self._drop("VIP_AFTER_SWITCH", addr, "S5")
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

    def _resolve_simultaneous_rekey(self, peer_id, addr=None):
        pending = [
            (pending_sid, state) for pending_sid, state in self.pending.items()
            if state.get("rekey") and state.get("peer_id") == peer_id
        ]
        if not pending:
            return True

        # A responder may already have accepted the peer's rekey M1 before its
        # own local threshold callback runs. That pending responder handshake is
        # authoritative; reject any second M1 rather than starting a parallel
        # responder exchange or letting the local threshold create another M1.
        if any(state.get("role") == "D" for _, state in pending):
            self._drop("NLS_REKEY_SIMULTANEOUS_LOST", addr, "D:M1")
            return False

        # If both initiators are pending, the lexicographically smaller router ID
        # wins. The winner keeps its outgoing M1; the loser aborts its outgoing
        # attempt and becomes the responder to the winner's M1.
        if self.owner.cfg.router_id < peer_id:
            self._drop("NLS_REKEY_SIMULTANEOUS_LOST", addr, "D:M1")
            return False
        for pending_sid, _state in pending:
            self._abort(pending_sid, "NLS_REKEY_SIMULTANEOUS_LOST", addr)
        return True

    def _handle_m1(self, packet, addr, sid):
        if sid in self.seen or sid in self.pending or sid in self.owner.sessions:
            self._drop("NLS_HS_REPLAY", addr, "D:M1")
            return
        if len(self.pending) >= MAX_PENDING:
            self._drop("NLS_HS_PENDING_LIMIT", addr, "D:M1")
            return
        failure_stage = "M1-decode"
        bootstrap_row_published = False
        try:
            kind, decoded_sid, obj, m1_plain = open_v2_message(packet, self.owner.encryption_private_key)
            if kind != M1 or decoded_sid != sid:
                raise ValueError("wrong message type")
            failure_stage = "M1-timestamp"
            verify_timestamp(obj["timestamp"])
            failure_stage = "M1-peer-record"
            record = self._cached_record(obj["router_id"])
            failure_stage = "M1-simultaneous-rekey"
            if not self._resolve_simultaneous_rekey(record["router_id"], addr):
                return
            failure_stage = "M1-ed25519-key"
            if obj["ed25519_public_key"] != _raw_ed25519(record):
                raise ValueError("M1 Ed25519 key differs from cached signed RDR")
            failure_stage = "M1-rsa-key"
            if _rsa_public({"rsa_encryption_public_key": obj["rsa_encryption_public_key"].decode("ascii")}).public_numbers() != _rsa_public(record).public_numbers():
                raise ValueError("M1 RSA key differs from cached signed RDR")
            failure_stage = "M1-signature"
            verify_v2_signature(M1, obj, _raw_ed25519(record))
            failure_stage = "M1-vip-source"
            if str(ipaddress.IPv6Address(addr[0])) != str(ipaddress.IPv6Address(obj["vip"])):
                raise ValueError("M1 vIP differs from observed source")
            failure_stage = "M1-record-validation"
            self._validate_record(record, fresh=False)
            failure_stage = "M1-revocation"
            if ca_client.is_revoked(record["certificate_serial"], self._settings()):
                raise ValueError("NLS_HS_REVOKED_M1")
            failure_stage = "M1-policy"
            policy = self._policy()
            failure_stage = "M1-local-record"
            local_record, local_envelope = self._self_record()
            local_cert = self._settings().certificate_file.read_bytes()
            failure_stage = "M1-local-certificate"
            self._certificate(local_cert, local_record)
            failure_stage = "M1-key-generation"
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
            failure_stage = "M1-M2-encode"
            obj2 = sign_v2(M2, obj2, self.owner.identity)
            packet2 = encode_v2_message(M2, sid, _rsa_public(record), obj2)
            if os.environ.get("NLS_HS_DIAGNOSTICS") == "1":
                self.log.info(
                    "NLS_HS_DATAGRAM_SIZE kind=M2 bytes=%d amplification_budget_bytes=%d "
                    "m2_max_datagram_bytes=%d ipv6_minimum_mtu=1280",
                    len(packet2), len(packet), M2_MAX_DATAGRAM,
                )
            if len(packet2) > len(packet):
                raise ValueError("M2 exceeds received M1 amplification budget")
            # Persist the pending bootstrap row and handshake state before
            # sending M2. A responder must never emit M2 if it could not commit
            # the corresponding vIP reservation locally.
            from . import lsdb
            failure_stage = "M1-vip-verification-stage"
            candidate_certificate_der = base64.b64decode(
                record["certificate_der_b64"], validate=True
            )
            candidate_public_key_der = ed25519.Ed25519PublicKey.from_public_bytes(
                _raw_ed25519(record)
            ).public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self.vip_verification.stage(
                vip=str(ipaddress.IPv6Address(obj["vip"])),
                router_id=record["router_id"],
                original_ip=record["originalIP"],
                certificate_der=candidate_certificate_der,
                public_key_der=candidate_public_key_der,
                record_seq=int(record["record_seq"]),
                session_id=sid,
                status=record.get("status", ""),
                expires_at=time.time() + HANDSHAKE_TIMEOUT,
            )
            failure_stage = "M1-vip-table-reservation"
            lsdb.publish_bootstrap_vip(
                str(ipaddress.IPv6Address(obj["vip"])),
                record["router_id"], record["originalIP"],
                base64.b64encode(_raw_ed25519(record)).decode("ascii"),
                session_id=sid,
                expires_at=time.time() + HANDSHAKE_TIMEOUT,
                record_seq=int(record.get("record_seq", 0)),
            )
            bootstrap_row_published = True
            active_peer_session = any(
                session.peer_id == record["router_id"]
                and session.state in ("ESTABLISHED", "OVERLAP")
                for session in self.owner.sessions.values()
            )
            self.pending[sid] = {
                "role": "D", "state": "M2_SENT", "created": time.monotonic(),
                "peer_id": record["router_id"], "rekey": active_peer_session,
                "peer_record": record, "local_record": local_record,
                "local_envelope": local_envelope, "m1": obj, "m1_plain": m1_plain,
                "m2": obj2, "m2_plain": __import__("cbor2").dumps(obj2, canonical=True),
                "eph": eph, "source_addr": addr, "vip": obj["vip"],
                "peer_endpoint": _endpoint_from_record(record),
            }
            self.seen[sid] = time.monotonic() + PENDING_REPLAY_TTL
            failure_stage = "M1-M2-send"
            self.owner.sock.sendto(packet2, addr)
        except Exception as exc:
            # Any row staged for this handshake contains temporary certificate
            # material. Remove it even if the failure happened before pending
            # state was inserted or the bootstrap LSDB row was written.
            try:
                self.vip_verification.remove(sid)
            except Exception:
                self._drop("NLS_VIP_VERIFICATION_CLEANUP_FAILED", addr, "D:M1")
            # A bootstrap row is written only after the incoming M1 is fully
            # screened. Do not delete a row based on an unauthenticated M1.
            if bootstrap_row_published:
                self.pending.pop(sid, None)
                self.seen.pop(sid, None)
                try:
                    from . import lsdb
                    lsdb.remove(str(ipaddress.IPv6Address(obj["vip"])), session_id=sid)
                except Exception:
                    pass
            if failure_stage == "M1-M2-encode" and os.environ.get("NLS_HS_DIAGNOSTICS") == "1":
                # Opt-in diagnostics only; disabled by default.
                message = str(exc)
                error_code = message if __import__("re").fullmatch(r"NLS_HS_[A-Z0-9_]+", message) else type(exc).__name__
                try:
                    import cbor2
                    m2_plaintext_bytes = len(cbor2.dumps(obj2, canonical=True))
                    m2_predicted_wire_bytes = 24 + 2 + 384 + 12 + 16 + m2_plaintext_bytes
                except Exception:
                    m2_plaintext_bytes = -1
                    m2_predicted_wire_bytes = -1
                m3_plaintext_bytes = -1
                m3_predicted_wire_bytes = -1
                try:
                    # Build a size-only M3 projection from the cached signed RDR.
                    # Placeholder values preserve the exact encoded lengths; no packet is sent.
                    cache, bundle = ca_client._load_verified_cache(self._settings())
                    envelopes = list(cache.get("lookups", {}).values())
                    if bundle:
                        envelopes.extend(bundle.get("records", []))
                    m3_envelope = next(
                        env for env in envelopes
                        if env.get("payload", {}).get("router_id") == record.get("router_id")
                    )
                    certificate_der = base64.b64decode(record["certificate_der_b64"], validate=True)
                    certificate_pem = x509.load_der_x509_certificate(certificate_der).public_bytes(
                        serialization.Encoding.PEM
                    )
                    m3_projection = {
                        "session_id": sid, "certificate": certificate_pem, "RDR": m3_envelope,
                        "dh_pub_S": bytes(32), "chosen_sa": SUITE,
                        "S.wan_endpoint": _endpoint_from_record(record),
                        "H2": bytes(32), "sig_S": bytes(64),
                    }
                    m3_plaintext_bytes = len(cbor2.dumps(m3_projection, canonical=True))
                    m3_predicted_wire_bytes = 24 + 2 + 384 + 12 + 16 + m3_plaintext_bytes
                except Exception:
                    pass
                self.log.warning(
                    "NLS_HS_ENCODE_DIAGNOSTIC error_code=%s traceback=%s "
                    "m1_packet_bytes=%d m2_cbor_bytes=%d m2_predicted_wire_bytes=%d "
                    "m3_cbor_projection_bytes=%d m3_predicted_wire_bytes=%d "
                    "amplification_budget_bytes=%d m2_max_datagram_bytes=%d "
                    "v2_max_cbor_bytes=16384 v2_max_datagram_bytes=20504 ipv6_minimum_mtu=1280",
                    error_code, "".join(traceback.format_tb(exc.__traceback__)),
                    len(packet), m2_plaintext_bytes, m2_predicted_wire_bytes,
                    m3_plaintext_bytes, m3_predicted_wire_bytes,
                    len(packet), M2_MAX_DATAGRAM,
                )
            self._drop(
                "NLS_HS_M1_REJECTED", addr, "D:M1",
                error_type=f"{type(exc).__module__}.{type(exc).__name__}",
                error_stage=failure_stage,
            )

    def _handle_m2(self, packet, addr, sid):
        state = self.pending.get(sid)
        if not state or state.get("role") != "S" or state.get("state") != "M1_SENT":
            self._drop("NLS_HS_OUT_OF_ORDER", addr, "S:M2")
            return
        failure_stage = "M2-decode"
        try:
            kind, decoded_sid, obj, m2_plain = open_v2_message(packet, self.owner.encryption_private_key)
            if kind != M2 or decoded_sid != sid:
                raise ValueError("wrong message type")
            failure_stage = "M2-fresh-peer-record"
            record, envelope = self._record_envelope(state["peer_id"])
            failure_stage = "M2-router-id"
            if obj["router_id"] != record["router_id"]:
                raise ValueError("M2 router ID differs from fresh S3 lookup")
            failure_stage = "M2-gateway-ips"
            if obj["gateway_ips"] != record.get("gateway_ips", []):
                raise ValueError("M2 gateway IPs differ from fresh S3 lookup")
            failure_stage = "M2-record-envelope"
            self.compare_fresh_record(
                ca_client._verify_directory_envelope(obj["RDR"], self._settings()), record, "S3"
            )
            failure_stage = "M2-record-validation"
            self._validate_record(record, fresh=True)
            failure_stage = "M2-certificate"
            self._certificate(obj["certificate"], record)
            failure_stage = "M2-signature"
            verify_v2_signature(M2, obj, _raw_ed25519(record))
            failure_stage = "M2-transcript"
            if obj["H1"] != transcript_h1(state["m1_plain"]):
                raise ValueError("M2 H1 transcript mismatch")
            failure_stage = "M2-suite"
            self.validate_suite(SUITE, obj["sa_proposals"], self._policy())
            failure_stage = "M2-source-endpoint"
            expected_endpoint = _normalized_endpoint(_endpoint_from_record(record))
            if (str(ipaddress.ip_address(addr[0])), int(addr[1])) != expected_endpoint:
                raise ValueError("M2 source endpoint mismatch")
            if _normalized_endpoint(state["peer_endpoint"]) != expected_endpoint:
                raise ValueError("peer endpoint changed")
            failure_stage = "M2-local-record"
            eph = x25519.X25519PrivateKey.generate()
            local_record, local_envelope = self._record_envelope(self.owner.cfg.router_id)
            local_cert = self._settings().certificate_file.read_bytes()
            failure_stage = "M2-local-certificate"
            self._certificate(local_cert, local_record)
            failure_stage = "M2-key-derivation"
            h2 = transcript_h2(state["m1_plain"], m2_plain)
            obj3 = {
                "session_id": sid, "certificate": local_cert, "RDR": local_envelope,
                "dh_pub_S": eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
                "chosen_sa": SUITE, "S.wan_endpoint": _endpoint_from_record(local_record),
                "H2": h2,
            }
            failure_stage = "M2-M3-encode"
            obj3 = sign_v2(M3, obj3, self.owner.identity)
            packet3 = encode_v2_message(M3, sid, _rsa_public(record), obj3)
            if os.environ.get("NLS_HS_DIAGNOSTICS") == "1":
                self.log.info(
                    "NLS_HS_DATAGRAM_SIZE kind=M3 bytes=%d m2_max_datagram_bytes=%d ipv6_minimum_mtu=1280",
                    len(packet3), M2_MAX_DATAGRAM,
                )
            state.update({"state": "M3_SENT", "peer_record": record, "peer_envelope": envelope,
                          "local_record": local_record, "local_envelope": local_envelope,
                          "m2": obj, "m2_plain": m2_plain, "m3": obj3,
                          "m3_plain": __import__("cbor2").dumps(obj3, canonical=True), "eph": eph})
            failure_stage = "M2-M3-send"
            state["vip_sock"].sendto(packet3, _normalized_endpoint(_endpoint_from_record(record)))
        except Exception as exc:
            self._abort(
                sid, "NLS_HS_S3_REJECTED", addr,
                error_type=f"{type(exc).__module__}.{type(exc).__name__}",
                error_stage=failure_stage,
            )

    def _handle_m3(self, packet, addr, sid):
        state = self.pending.get(sid)
        if not state or state.get("role") != "D" or state.get("state") != "M2_SENT":
            self._drop("NLS_HS_OUT_OF_ORDER", addr, "D:M3")
            return
        failure_stage = "M3-vip-source"
        try:
            if str(ipaddress.IPv6Address(addr[0])) != str(ipaddress.IPv6Address(state["vip"])):
                raise ValueError("M3 did not arrive from bootstrap vIP")
            failure_stage = "M3-decode"
            kind, decoded_sid, obj, m3_plain = open_v2_message(packet, self.owner.encryption_private_key)
            if kind != M3 or decoded_sid != sid:
                raise ValueError("wrong message type")
            failure_stage = "M3-fresh-peer-record"
            fresh, envelope = self._record_envelope(state["m1"]["router_id"])
            failure_stage = "M3-record-envelope"
            embedded = ca_client._verify_directory_envelope(obj["RDR"], self._settings())
            failure_stage = "M3-record-comparison"
            self.compare_fresh_record(embedded, fresh, "S4")
            failure_stage = "M3-ed25519-key"
            if state["m1"]["ed25519_public_key"] != _raw_ed25519(fresh):
                raise ValueError("M1 Ed25519 key differs from fresh S4 RDR")
            failure_stage = "M3-rsa-key"
            m1_rsa = _rsa_public({"rsa_encryption_public_key": state["m1"]["rsa_encryption_public_key"].decode("ascii")})
            if m1_rsa.public_numbers() != _rsa_public(fresh).public_numbers():
                raise ValueError("M1 RSA key differs from fresh S4 RDR")
            failure_stage = "M3-wan-endpoint"
            if obj["S.wan_endpoint"] not in fresh.get("wan_endpoints", []):
                raise ValueError("M3 WAN endpoint is not CA-authorized")
            failure_stage = "M3-suite"
            self.validate_suite(obj["chosen_sa"], [obj["chosen_sa"]], {
                "allowed_suites": self._policy()["allowed_suites"]
            })
            failure_stage = "M3-transcript"
            if obj["H2"] != transcript_h2(state["m1_plain"], state["m2_plain"]):
                raise ValueError("M3 H2 transcript mismatch")
            failure_stage = "M3-certificate"
            self._certificate(obj["certificate"], fresh)
            failure_stage = "M3-signature"
            verify_v2_signature(M3, obj, _raw_ed25519(fresh))
            failure_stage = "M3-vip-table-cross-check"
            candidate_certificate_der = self._certificate_der(obj["certificate"])
            candidate_public_key_der = ed25519.Ed25519PublicKey.from_public_bytes(
                _raw_ed25519(fresh)
            ).public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            failure_stage = "M3-key-derivation"
            h3 = transcript_h3(state["m1_plain"], state["m2_plain"], m3_plain)
            keys = derive_session_keys(state["eph"], obj["dh_pub_S"], h3, sid)
            failure_stage = "M3-local-record"
            local_record, local_envelope = self._self_record()
            local_cert = self._settings().certificate_file.read_bytes()
            self._certificate(local_cert, local_record)
            failure_stage = "M3-confirmation"
            obj4 = {
                "session_id": sid, "trust": True, "H3": h3,
                "confirm": __import__("nls.key_schedule", fromlist=["confirmation_mac"]).confirmation_mac(keys["k_confirm"], h3),
            }
            obj4 = sign_v2(M4, obj4, self.owner.identity)
            packet4 = encode_v2_message(M4, sid, _rsa_public(fresh), obj4)
            # Prepare token state before acknowledging M4; activate only after send.
            failure_stage = "M3-session-prepare"
            prepared_session = self._session(
                fresh, sid, obj["S.wan_endpoint"], keys,
                "d_to_s_key", "s_to_d_key", state["vip"],
                local_record=state.get("local_record"),
                source_token_context={
                    "role": "D", "h3": h3,
                    "nonce_s": state["m1"]["nonce_s"],
                    "nonce_d": state["m2"]["nonce_d"],
                },
                activate=False,
            )
            # Finish exact table matching before sending M4. If the live CA record
            # changed since M1, fail closed without giving the initiator an M4 it
            # could accept while this router rejects the same handshake.
            failure_stage = "M3-vip-table-cross-check"
            self.vip_verification.verify(
                session_id=sid,
                vip=str(ipaddress.IPv6Address(state["vip"])),
                router_id=fresh["router_id"],
                original_ip=fresh["originalIP"],
                certificate_der=candidate_certificate_der,
                public_key_der=candidate_public_key_der,
                record_seq=int(fresh["record_seq"]),
                ca_record_verified=True,
                destination_signature_verified=True,
            )
            try:
                failure_stage = "M3-M4-send"
                self.owner.sock.sendto(packet4, state["source_addr"])
            except Exception:
                self._discard_prepared_session(prepared_session)
                raise
            self.retired_vips[str(ipaddress.IPv6Address(state["vip"]))] = time.monotonic() + PENDING_REPLAY_TTL
            # The temporary bootstrap identity is retired after M4 is sent;
            # publish only the derived directional SourceTokens as active rows.
            from . import lsdb
            lsdb.remove(str(ipaddress.IPv6Address(state["vip"])), session_id=sid)
            failure_stage = "M3-session-install"
            try:
                self._activate_session(prepared_session, flush_pending=False)
            except Exception:
                self._discard_prepared_session(prepared_session)
                raise
            self.pending.pop(sid, None)
            self.owner._flush_pending(fresh["router_id"])
        except Exception as exc:
            self._abort(
                sid, "NLS_HS_S4_REJECTED", addr,
                error_type=f"{type(exc).__module__}.{type(exc).__name__}",
                error_stage=failure_stage,
            )

    def _handle_m4(self, packet, addr, sid):
        state = self.pending.get(sid)
        if not state or state.get("role") != "S" or state.get("state") != "M3_SENT":
            self._drop("NLS_HS_OUT_OF_ORDER", addr, "S:M4")
            return
        failure_stage = "M4-decode"
        try:
            kind, decoded_sid, obj, _m4_plain = open_v2_message(packet, self.owner.encryption_private_key)
            if kind != M4 or decoded_sid != sid:
                raise ValueError("wrong message type")
            record = state["peer_record"]
            failure_stage = "M4-source-endpoint"
            if (str(ipaddress.ip_address(addr[0])), int(addr[1])) != _normalized_endpoint(_endpoint_from_record(record)):
                raise ValueError("M4 source endpoint mismatch")
            failure_stage = "M4-signature"
            verify_v2_signature(M4, obj, _raw_ed25519(record))
            failure_stage = "M4-transcript"
            expected_h3 = transcript_h3(state["m1_plain"], state["m2_plain"], state["m3_plain"])
            if obj["H3"] != expected_h3:
                raise ValueError("M4 H3 transcript mismatch")
            failure_stage = "M4-key-derivation"
            keys = derive_session_keys(state["eph"], state["m2"]["dh_pub_D"], expected_h3, sid)
            failure_stage = "M4-confirmation"
            verify_confirmation(keys["k_confirm"], expected_h3, obj["confirm"])
            failure_stage = "M4-trust-flag"
            if obj["trust"] is not True:
                raise ValueError("M4 trust flag false")
            # M4 is accepted only after signature, transcript, and key-confirmation
            # checks. It proves the destination router accepted this staged identity.
            failure_stage = "M4-vip-table-cross-check"
            local_record = state.get("local_record") or self._self_record()[0]
            local_certificate_der = self._certificate_der(
                self._settings().certificate_file.read_bytes()
            )
            local_public_key_der = ed25519.Ed25519PublicKey.from_public_bytes(
                self.owner.identity_raw
            ).public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self.vip_verification.verify(
                session_id=sid,
                vip=str(ipaddress.IPv6Address(state["vip"])),
                router_id=local_record["router_id"],
                original_ip=local_record["originalIP"],
                certificate_der=local_certificate_der,
                public_key_der=local_public_key_der,
                record_seq=int(local_record["record_seq"]),
                ca_record_verified=True,
                destination_signature_verified=True,
            )
            vip = state["vip"]
            sock = state["vip_sock"]
            failure_stage = "M4-vip-release"
            sock.close()
            self.vip_sockets.pop(sid, None)
            # Do not expose an established session until the bootstrap address
            # has actually been removed from the kernel.
            self.vip.release(vip)
            self.retired_vips[str(ipaddress.IPv6Address(vip))] = time.monotonic() + PENDING_REPLAY_TTL
            # Successful M4 confirms the responder. Remove the temporary
            # bootstrap row before publishing established SourceToken bindings.
            from . import lsdb
            lsdb.remove(str(ipaddress.IPv6Address(vip)), session_id=sid)
            failure_stage = "M4-session-install"
            self._session(
                record, sid, _endpoint_from_record(record), keys,
                "s_to_d_key", "d_to_s_key", vip=vip,
                local_record=state.get("local_record"),
                source_token_context={
                    "role": "S", "h3": expected_h3,
                    "nonce_s": state["m1"]["nonce_s"],
                    "nonce_d": state["m2"]["nonce_d"],
                },
            )
            self.pending.pop(sid, None)
        except Exception as exc:
            self._abort(
                sid, "NLS_HS_M4_REJECTED", addr,
                error_type=f"{type(exc).__module__}.{type(exc).__name__}",
                error_stage=failure_stage,
            )

    def _abort(self, sid: bytes, reason: str, addr=None, *, error_type=None, error_stage=None):
        state = self.pending.pop(sid, None)
        if state:
            # Drop certificate/public-key staging material on any failed or timed-out
            # handshake. It is intentionally separate from authenticated LSDB rows.
            try:
                self.vip_verification.remove(sid)
            except Exception:
                self._drop("NLS_VIP_VERIFICATION_CLEANUP_FAILED", addr, state.get("state", "unknown"))
            # Remove any pending bootstrap row on every abort path. The session
            # ID guard prevents a timeout from deleting a newer generation.
            try:
                from . import lsdb
                vip_entry = state.get("vip")
                if vip_entry:
                    lsdb.remove(str(ipaddress.IPv6Address(vip_entry)), session_id=sid)
            except Exception:
                self._drop("NLS_VIP_TABLE_CLEANUP_FAILED", addr, state.get("state", "unknown"))
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
                try:
                    self.vip.release(vip)
                except Exception:
                    self._drop("NLS_VIP_CLEANUP_FAILED", addr, state.get("state", "unknown"))
        self._drop(
            reason, addr, state.get("state", "unknown") if state else "unknown",
            error_type=error_type, error_stage=error_stage,
        )

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
        # Recover using the interface and pool recorded by the previous process,
        # even when the current config leaves bind_interface empty or has changed.
        try:
            data = json.loads(VIP_STATE_PATH.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if self.vip:
                self.vip.cleanup_startup()
            return
        except (OSError, ValueError, TypeError) as exc:
            raise RuntimeError("unable to read vIP recovery state") from exc
        if not isinstance(data, dict) or data.get("version") != 1:
            raise RuntimeError("invalid vIP recovery state")
        interface = data.get("interface")
        pool = data.get("pool", DEFAULT_POOL)
        if not isinstance(interface, str) or not isinstance(pool, str):
            raise RuntimeError("invalid vIP recovery interface or pool")
        recovery = VIPManager(interface, pool=pool, state_path=VIP_STATE_PATH)
        recovery.cleanup_startup()
        if self.owner.cfg.bind_interface:
            self.vip = VIPManager(self.owner.cfg.bind_interface)
        else:
            # The interface for a new handshake is selected from the peer route.
            self.vip = None

    def close(self):
        for sid in list(self.pending):
            self._abort(sid, "NLS_HS_SHUTDOWN")
        if self.vip:
            self.vip.release_all()
