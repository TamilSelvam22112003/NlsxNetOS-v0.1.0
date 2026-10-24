"""Explicit session-scoped NLS Trust Table.

The Trust Table records authorization decisions only after VIPVerificationTable
has independently cross-checked the peer-presented RDR against the Router-CA
record. It stores fingerprints, not certificates, private keys, or traffic keys.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

DEFAULT_STATE_PATH = Path(os.environ.get(
    "NLSXNETOS_TRUST_TABLE", "/run/nlsxnetos/trust-table.json"
))
TABLE_VERSION = 1
DEFAULT_SESSION_TTL = 3600.0
_LOCK = threading.RLock()


def _sid(value) -> str:
    result = value.hex() if isinstance(value, bytes) else str(value or "")
    if not result or result == "None" or len(result) > 128:
        raise ValueError("session_id is required")
    return result


class TrustTable:
    """Persist verified peer/session trust separately from vIP staging rows."""

    def __init__(self, state_path: str | Path | None = None):
        self.state_path = Path(state_path) if state_path is not None else DEFAULT_STATE_PATH

    def _load(self) -> dict:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise RuntimeError("NLS Trust Table is unreadable") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("_table_version") != TABLE_VERSION
            or not isinstance(payload.get("entries"), dict)
        ):
            raise RuntimeError("NLS Trust Table schema is invalid")
        return payload["entries"]

    def _save(self, entries: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        temp = self.state_path.with_name(
            f"{self.state_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(
                    {"_table_version": TABLE_VERSION, "entries": entries,
                     "updated_at": int(time.time())},
                    stream, sort_keys=True, separators=(",", ":"),
                )
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
            return {key: dict(row) for key, row in live.items()}

    def get(self, session_id) -> dict | None:
        return self.entries().get(_sid(session_id))

    def record_verified_vip(
        self, vip_row: dict, *, session_ttl: float = DEFAULT_SESSION_TTL
    ) -> dict:
        """Authorize a session only from a VERIFIED, cross-checked VIP row."""
        if not isinstance(vip_row, dict) or vip_row.get("status") != "VERIFIED":
            raise ValueError("Trust Table requires a VERIFIED VIP row")
        if not 0 < float(session_ttl) <= 86400:
            raise ValueError("trust session TTL must be within 24 hours")
        required_checks = (
            "router_ca_record", "destination_router", "certificate_match",
            "public_key_match", "original_ip_match", "record_seq_match",
        )
        checks = vip_row.get("verification")
        if not isinstance(checks, dict) or any(checks.get(name) is not True for name in required_checks):
            raise ValueError("VIP row lacks complete cross-verification evidence")
        sid = _sid(vip_row.get("session_id"))
        router_id = vip_row.get("router_id")
        original_ip = vip_row.get("original_ip")
        vip = vip_row.get("vip")
        cert_hash = vip_row.get("certificate_sha256")
        key_hash = vip_row.get("public_key_sha256")
        if not all(isinstance(v, str) and v for v in (router_id, original_ip, vip, cert_hash, key_hash)):
            raise ValueError("verified VIP row is missing identity fingerprints")
        # The VIP table must have retained both independently sourced values.
        equality_pairs = (
            ("dest_router_ip", "dest_router_ip_from_router_ca"),
            ("dest_router_certificate", "dest_router_certificate_from_router_ca"),
            ("dest_router_public_key", "dest_router_public_key_from_router_ca"),
        )
        if any(vip_row.get(left) != vip_row.get(right) for left, right in equality_pairs):
            raise ValueError("VIP destination and Router-CA identity values differ")
        cert_b64 = vip_row.get("dest_router_certificate")
        key_b64 = vip_row.get("dest_router_public_key")
        if not isinstance(cert_b64, str) or not isinstance(key_b64, str):
            raise ValueError("verified VIP certificate/public key material is missing")
        import base64
        try:
            cert = base64.b64decode(cert_b64.encode("ascii"), validate=True)
            key = base64.b64decode(key_b64.encode("ascii"), validate=True)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("verified VIP certificate/public key encoding is invalid") from exc
        if hashlib.sha256(cert).hexdigest() != cert_hash:
            raise ValueError("VIP certificate fingerprint changed after verification")
        # public_key_sha256 in VIP table is SPKI DER, while the cross-check fields
        # retain the raw Ed25519 public key; validate both independently.
        spki_b64 = vip_row.get("public_key_der_b64")
        if not isinstance(spki_b64, str):
            raise ValueError("verified VIP SPKI encoding is missing")
        try:
            spki = base64.b64decode(spki_b64.encode("ascii"), validate=True)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("verified VIP SPKI encoding is invalid") from exc
        if hashlib.sha256(spki).hexdigest() != key_hash or not key:
            raise ValueError("VIP public-key fingerprint changed after verification")
        now = time.time()
        row = {
            "session_id": sid,
            "vip": vip,
            "router_id": router_id,
            "original_ip": original_ip,
            "certificate_sha256": cert_hash,
            "public_key_sha256": key_hash,
            "record_seq": vip_row.get("record_seq"),
            "state": "TRUSTED",
            "verified_at": now,
            "expires_at": now + float(session_ttl),
            "verification": {name: True for name in required_checks},
        }
        with _LOCK:
            rows = self.entries(now)
            previous = rows.get(sid)
            if previous and any(previous.get(field) != row[field] for field in (
                "vip", "router_id", "original_ip", "certificate_sha256",
                "public_key_sha256", "record_seq",
            )):
                raise ValueError("Trust Table session identity conflict")
            rows[sid] = row
            self._save(rows)
        return dict(row)

    def is_trusted(self, session_id) -> bool:
        row = self.get(session_id)
        return bool(row and row.get("state") == "TRUSTED")

    def remove(self, session_id) -> bool:
        sid = _sid(session_id)
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
                sid for sid, row in rows.items()
                if not isinstance(row, dict)
                or type(row.get("expires_at")) not in (int, float)
                or float(row["expires_at"]) <= current
            ]
            for sid in expired:
                rows.pop(sid, None)
            if expired:
                self._save(rows)
            return expired
