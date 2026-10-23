"""Short-lived vIP identity verification table for the NLH2 handshake.

Rows are staging records only. They are not routing entries and must never be
used to resolve or forward an original IP until certificate, Router Directory
Record, and handshake-peer checks all agree. Rows are session-scoped and expire
within the handshake lifetime.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import threading
import time
from pathlib import Path

DEFAULT_STATE_PATH = Path(os.environ.get(
    "NLSXNETOS_VIP_VERIFY_TABLE",
    "/run/nlsxnetos/vip-verification.json",
))
TABLE_VERSION = 1
MAX_TTL_SECONDS = 10.0
_LOCK = threading.RLock()


def _ipv6(value, field: str) -> str:
    try:
        return str(ipaddress.IPv6Address(value))
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError(f"{field} must be an IPv6 address") from exc


def _session_key(session_id) -> str:
    value = session_id.hex() if isinstance(session_id, bytes) else str(session_id or "")
    if not value or value == "None" or len(value) > 128:
        raise ValueError("session_id is required")
    return value


def _decode_b64(value, field: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"{field} must be valid base64") from exc
    if not decoded or len(decoded) > maximum:
        raise ValueError(f"{field} length is invalid")
    return decoded


class VIPVerificationTable:
    """Atomic, session-scoped temporary table; never a source of route authority."""

    def __init__(
        self, state_path: str | Path | None = None, ttl: float = 10.0,
        router_id: str | None = None,
    ):
        if not 0 < float(ttl) <= MAX_TTL_SECONDS:
            raise ValueError("verification table TTL must be between 0 and 10 seconds")
        base_path = Path(state_path) if state_path is not None else DEFAULT_STATE_PATH
        if router_id is not None:
            if not isinstance(router_id, str) or not router_id or len(router_id) > 128:
                raise ValueError("router_id is invalid")
            # Network namespaces share /run in the CI lab; isolate state by router
            # identity so one daemon cannot erase another daemon's staged row.
            suffix = hashlib.sha256(router_id.encode("utf-8")).hexdigest()[:12]
            self.state_path = base_path.with_name(
                f"{base_path.stem}.{suffix}{base_path.suffix}"
            )
        else:
            self.state_path = base_path
        self.ttl = float(ttl)

    def _load(self) -> dict:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise RuntimeError("vIP verification table is unreadable") from exc
        if (
            not isinstance(data, dict)
            or data.get("_table_version") != TABLE_VERSION
            or not isinstance(data.get("entries"), dict)
        ):
            raise RuntimeError("vIP verification table schema is invalid")
        return data["entries"]

    def _save(self, entries: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        temp = self.state_path.with_name(
            f"{self.state_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({
                    "_table_version": TABLE_VERSION,
                    "entries": entries,
                    "updated_at": int(time.time()),
                }, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.state_path)
            os.chmod(self.state_path, 0o600)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def entries(self, now: float | None = None) -> dict:
        current = time.time() if now is None else float(now)
        with _LOCK:
            rows = self._load()
            live = {
                key: row for key, row in rows.items()
                if isinstance(row, dict)
                and type(row.get("expires_at")) in (int, float)
                and float(row["expires_at"]) > current
            }
            if live != rows:
                self._save(live)
            return {key: dict(value) for key, value in live.items()}

    def get(self, session_id) -> dict | None:
        key = _session_key(session_id)
        return self.entries().get(key)

    def stage(
        self, *, vip: str, router_id: str, original_ip: str,
        certificate_der: bytes, public_key_der: bytes, record_seq: int,
        session_id, status: str = "ACTIVE", expires_at: float | None = None,
    ) -> dict:
        """Persist a candidate from a verified signed RDR as PENDING, never trusted."""
        vip = _ipv6(vip, "vIP")
        original_ip = _ipv6(original_ip, "original IP")
        sid = _session_key(session_id)
        if not isinstance(router_id, str) or not router_id or len(router_id) > 128:
            raise ValueError("router_id is invalid")
        if status != "ACTIVE":
            raise ValueError("Router-CA record must be ACTIVE")
        if type(record_seq) is not int or record_seq < 1:
            raise ValueError("Router-CA record sequence is invalid")
        cert = bytes(certificate_der)
        key_der = bytes(public_key_der)
        if not cert or len(cert) > 16384:
            raise ValueError("certificate DER length is invalid")
        if not key_der or len(key_der) > 2048:
            raise ValueError("public-key DER length is invalid")
        now = time.time()
        deadline = min(
            float(expires_at) if expires_at is not None else now + self.ttl,
            now + self.ttl,
        )
        if deadline <= now:
            raise ValueError("vIP verification row expiry must be in the future")
        row = {
            "vip": vip,
            "router_id": router_id,
            "original_ip": original_ip,
            "certificate_der_b64": base64.b64encode(cert).decode("ascii"),
            "certificate_sha256": hashlib.sha256(cert).hexdigest(),
            "public_key_der_b64": base64.b64encode(key_der).decode("ascii"),
            "public_key_sha256": hashlib.sha256(key_der).hexdigest(),
            "record_seq": record_seq,
            "session_id": sid,
            "status": "PENDING",
            "ca_status": status,
            "created_at": now,
            "expires_at": deadline,
        }
        with _LOCK:
            rows = self.entries(now)
            old = rows.get(sid)
            if old is not None and any(old.get(field) != row[field] for field in (
                "vip", "router_id", "original_ip", "certificate_sha256",
                "public_key_sha256", "record_seq",
            )):
                raise ValueError("vIP verification row conflicts with existing session")
            rows[sid] = old if old and old.get("status") == "VERIFIED" else row
            self._save(rows)
            return dict(rows[sid])

    def verify(
        self, *, session_id, vip: str, router_id: str, original_ip: str,
        certificate_der: bytes, public_key_der: bytes, record_seq: int,
        ca_record_verified: bool, destination_signature_verified: bool,
        destination_record: dict | None = None, router_ca_record: dict | None = None,
    ) -> dict:
        """Promote only when the peer-presented RDR and independently verified CA RDR agree."""
        if ca_record_verified is not True or destination_signature_verified is not True:
            raise ValueError("Router-CA and destination-router verification are required")
        sid = _session_key(session_id)
        vip = _ipv6(vip, "vIP")
        original_ip = _ipv6(original_ip, "original IP")
        cert = bytes(certificate_der)
        key_der = bytes(public_key_der)
        if not isinstance(destination_record, dict) or not isinstance(router_ca_record, dict):
            raise ValueError("both destination-router and Router-CA identity records are required")
        stable_fields = (
            "router_id", "originalIP", "ed25519_public_key",
            "ed25519_public_key_spki_der_b64", "rsa_encryption_public_key",
            "certificate_der_b64", "wan_endpoints", "gateway_ips", "prefixes",
            "certificate_serial",
        )
        if destination_record.get("status") != "ACTIVE" or router_ca_record.get("status") != "ACTIVE":
            raise ValueError("destination-router and Router-CA records must both be ACTIVE")
        if any(destination_record.get(field) != router_ca_record.get(field) for field in stable_fields):
            raise ValueError("destination-router identity does not match Router-CA identity")
        try:
            record_cert = base64.b64decode(destination_record["certificate_der_b64"], validate=True)
            record_key_der = base64.b64decode(destination_record["ed25519_public_key_spki_der_b64"], validate=True)
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError("destination-router certificate/public key encoding is invalid") from exc
        if record_cert != cert or record_key_der != key_der:
            raise ValueError("verified certificate/public key differs from cross-checked records")
        if destination_record.get("router_id") != router_id or destination_record.get("originalIP") != original_ip:
            raise ValueError("destination-router IP or router identity does not match verification row")
        with _LOCK:
            rows = self.entries()
            row = rows.get(sid)
            if row is None:
                raise ValueError("vIP verification row is missing or expired")
            comparisons = {
                "vip": vip,
                "router_id": router_id,
                "original_ip": original_ip,
                "certificate_sha256": hashlib.sha256(cert).hexdigest(),
                "public_key_sha256": hashlib.sha256(key_der).hexdigest(),
                "record_seq": record_seq,
            }
            if any(row.get(field) != value for field, value in comparisons.items()):
                raise ValueError("vIP verification details do not match Router-CA and peer")
            if row.get("ca_status") != "ACTIVE" or row.get("status") not in ("PENDING", "VERIFIED"):
                raise ValueError("vIP verification row is not eligible for promotion")
            row["status"] = "VERIFIED"
            row["verified_at"] = time.time()
            # Keep peer-presented and Router-CA identity values in distinct columns.
            # Raw session keys are deliberately not persisted; NLH2 derives them.
            row.update({
                "dest_router_ip": original_ip,
                "dest_router_ip_from_dest_router": destination_record["originalIP"],
                "dest_router_public_key": destination_record["ed25519_public_key"],
                "dest_router_certificate": destination_record["certificate_der_b64"],
                "symmetric_key_from_dest_router": None,
                "dest_router_public_key_from_router_ca": router_ca_record["ed25519_public_key"],
                "dest_router_certificate_from_router_ca": router_ca_record["certificate_der_b64"],
                "dest_router_ip_from_router_ca": router_ca_record["originalIP"],
                "timestamp": row.get("created_at"),
                "key_establishment": "X25519-HKDF-SHA256",
            })
            row["verification"] = {
                "router_ca_record": True,
                "destination_router": True,
                "certificate_match": True,
                "public_key_match": True,
                "original_ip_match": True,
                "record_seq_match": True,
            }
            rows[sid] = row
            self._save(rows)
            return dict(row)

    def is_verified(self, session_id) -> bool:
        row = self.get(session_id)
        return bool(row and row.get("status") == "VERIFIED")

    def remove(self, session_id) -> bool:
        sid = _session_key(session_id)
        with _LOCK:
            rows = self._load()
            if sid not in rows:
                return False
            rows.pop(sid, None)
            self._save(rows)
            return True

    def expire(self, now: float | None = None) -> list[str]:
        current = time.time() if now is None else float(now)
        with _LOCK:
            rows = self._load()
            expired = [
                key for key, row in rows.items()
                if not isinstance(row, dict)
                or type(row.get("expires_at")) not in (int, float)
                or float(row["expires_at"]) <= current
            ]
            for key in expired:
                rows.pop(key, None)
            if expired:
                self._save(rows)
            return expired
