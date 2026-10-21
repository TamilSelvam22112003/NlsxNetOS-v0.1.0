"""Persistent table for temporary NLH2 virtual-IP reservations.

This table is separate from the kernel address allocator in nls.vip and the
established SourceToken/originalIP records in nls.lsdb. PENDING rows are
handshake bookkeeping only, never a route or an OSPF LSA.
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from pathlib import Path

STATE_PATH = Path(os.environ.get(
    "NLSXNETOS_VIP_TABLE_STATE", "/run/nlsxnetos/nls-vip-table.json"
))
TABLE_VERSION = 1
_LOCK = threading.RLock()


def _canonical_ipv6(value, field):
    try:
        return str(ipaddress.IPv6Address(value))
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError(f"{field} must be an IPv6 address") from exc


def _session_key(value):
    if isinstance(value, bytes):
        value = value.hex()
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError("vIP reservation session identifier invalid")
    return value


def _load():
    if not STATE_PATH.exists():
        return {}
    try:
        document = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        # Never reset unreadable collision/ownership state while handshakes may
        # still be pending. Fail closed so the service operator can investigate.
        raise RuntimeError("NLS vIP table state is unreadable") from exc
    if not isinstance(document, dict) or document.get("_table_version") != TABLE_VERSION:
        raise RuntimeError("unsupported NLS vIP table version")
    rows = document.get("entries")
    if not isinstance(rows, dict):
        raise RuntimeError("NLS vIP table entries are invalid")
    return rows


def _save(rows):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    document = {
        "_table_version": TABLE_VERSION,
        "entries": rows,
        "updated_at": int(time.time()),
    }
    temporary = STATE_PATH.with_name(STATE_PATH.name + f".{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATE_PATH)
        os.chmod(STATE_PATH, 0o640)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _normalize(vip, row, now):
    if not isinstance(row, dict):
        return None
    try:
        key = _canonical_ipv6(vip, "vIP")
        router_id = row["router_id"]
        original_ip = _canonical_ipv6(row["original_ip"], "original IP")
        identity_public_key = row["identity_public_key"]
        session_id = _session_key(row["session_id"])
        record_seq = row["record_seq"]
        expires_at = float(row["expires_at"])
        if not isinstance(router_id, str) or not router_id:
            return None
        if not isinstance(identity_public_key, str) or not identity_public_key:
            return None
        if type(record_seq) is not int or record_seq < 0:
            return None
        if row.get("record_type") != "vip_reservation":
            return None
        if row.get("state") != "PENDING" or row.get("authenticated") is not False:
            return None
        if expires_at <= now:
            return None
        normalized = dict(row)
        normalized.update({
            "vip": key,
            "router_id": router_id,
            "original_ip": original_ip,
            "originalIP": original_ip,
            "identity_public_key": identity_public_key,
            "session_id": session_id,
            "record_seq": record_seq,
            "record_type": "vip_reservation",
            "state": "PENDING",
            "authenticated": False,
            "expires_at": expires_at,
        })
        return normalized
    except (KeyError, TypeError, ValueError):
        return None


def expire(now=None):
    """Delete expired/malformed reservations and return the retained snapshot."""
    now = time.time() if now is None else float(now)
    with _LOCK:
        stored = _load()
        retained = {}
        for vip, row in stored.items():
            normalized = _normalize(vip, row, now)
            if normalized is not None:
                retained[normalized["vip"]] = normalized
        if retained != stored:
            _save(retained)
        return retained


def entries(now=None):
    """Return a copy of the current non-expired reservation table."""
    return {key: dict(value) for key, value in expire(now).items()}


def get(vip, now=None):
    """Return one canonical vIP reservation, or None when absent/expired."""
    try:
        key = _canonical_ipv6(vip, "vIP")
    except ValueError:
        return None
    row = expire(now).get(key)
    return dict(row) if row is not None else None


def reserve(vip, router_id, original_ip, identity_public_key, *,
            session_id, expires_at, record_seq=0):
    """Atomically reserve one vIP for one bounded, unauthenticated handshake."""
    vip = _canonical_ipv6(vip, "vIP")
    original_ip = _canonical_ipv6(original_ip, "original IP")
    session_id = _session_key(session_id)
    if not isinstance(router_id, str) or not router_id:
        raise ValueError("vIP reservation router identity required")
    if not isinstance(identity_public_key, str) or not identity_public_key:
        raise ValueError("vIP reservation identity key required")
    if type(record_seq) is not int or record_seq < 0:
        raise ValueError("vIP reservation record sequence invalid")
    deadline = float(expires_at)
    now = time.time()
    if deadline <= now:
        raise ValueError("vIP reservation expiry must be in the future")

    candidate = {
        "router_id": router_id,
        "original_ip": original_ip,
        "originalIP": original_ip,
        "identity_public_key": identity_public_key,
        "session_id": session_id,
        "record_seq": record_seq,
        "record_type": "vip_reservation",
        "state": "PENDING",
        "authenticated": False,
        "expires_at": deadline,
        "updated_at": now,
    }
    with _LOCK:
        current = expire()
        old = current.get(vip)
        if old is not None:
            exact_owner = (
                old.get("router_id") == router_id
                and old.get("original_ip") == original_ip
                and old.get("identity_public_key") == identity_public_key
                and old.get("session_id") == session_id
                and old.get("record_seq") == record_seq
            )
            if not exact_owner:
                raise ValueError("vIP already reserved by another handshake")
            candidate["updated_at"] = old.get("updated_at", now)
        for old_vip, row in current.items():
            if old_vip != vip and row.get("session_id") == session_id:
                raise ValueError("handshake session already reserves another vIP")
        current[vip] = candidate
        _save(current)
        return dict(candidate, vip=vip)


def remove(vip, *, session_id=None):
    """Remove a reservation; an optional session ID prevents stale cleanup."""
    try:
        key = _canonical_ipv6(vip, "vIP")
    except ValueError:
        return False
    expected = _session_key(session_id) if session_id is not None else None
    with _LOCK:
        current = _load()
        row = current.get(key)
        if row is None:
            return False
        if expected is not None and row.get("session_id") != expected:
            return False
        current.pop(key, None)
        _save(current)
        return True
