"""NLS virtual-IP/SourceToken table and authenticated LSDB records.

The table is the control-plane view of vIP and SourceToken lifecycle. It never
installs kernel routes: routing remains exclusively operator-configured.
Only accepted, authenticated sessions may publish original-IP reachability.
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from pathlib import Path

STATE_PATH = Path(os.environ.get("NLSXNETOS_NLS_LSDB", "/run/nlsxnetos/nls-lsdb.json"))
TABLE_VERSION = 1
_DEFAULT_TTL = 300.0
_LOCK = threading.RLock()


def _canonical_ipv6(value, field):
    try:
        return str(ipaddress.IPv6Address(value))
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError(f"{field} must be an IPv6 address") from exc


def _load():
    if not STATE_PATH.exists():
        return {}
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        # A malformed LSDB must fail closed. Silently resetting it could erase
        # collision and trust state while live sessions still exist.
        raise RuntimeError("NLS vIP/LSDB state is unreadable") from exc
    if not isinstance(value, dict):
        raise RuntimeError("NLS vIP/LSDB state must be an object")
    if value.get("_table_version") != TABLE_VERSION:
        # Support the original unversioned map once, then write the versioned
        # shape on the next mutation. Invalid entries are discarded fail-closed.
        if "_table_version" in value:
            raise RuntimeError("unsupported NLS vIP/LSDB table version")
        return {k: v for k, v in value.items() if isinstance(v, dict)}
    entries = value.get("entries")
    if not isinstance(entries, dict):
        raise RuntimeError("NLS vIP/LSDB entries are invalid")
    return entries


def _save(entries):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    payload = {"_table_version": TABLE_VERSION, "entries": entries,
               "updated_at": int(time.time())}
    tmp = STATE_PATH.with_name(STATE_PATH.name + f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, STATE_PATH)
        os.chmod(STATE_PATH, 0o640)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _normalized_entry(vip, entry, now):
    if not isinstance(entry, dict):
        return None
    try:
        expires_at = float(entry["expires_at"])
        if expires_at <= now:
            return None
        router_id = str(entry["router_id"])
        original_ip = _canonical_ipv6(entry["original_ip"], "original IP")
        record_type = str(entry.get("record_type", "source_token"))
        if record_type == "bootstrap_vip":
            # Bootstrap rows are intentionally unauthenticated and have no
            # SourceToken yet. They are useful for timeout/collision cleanup,
            # never for original-IP resolution or forwarding.
            token_value = entry.get("source_token")
            token = _canonical_ipv6(token_value, "SourceToken") if token_value else None
            if entry.get("authenticated") is not False or entry.get("state") != "PENDING":
                return None
        elif record_type == "source_token":
            token = _canonical_ipv6(entry.get("source_token", vip), "SourceToken")
        else:
            return None
        state = str(entry.get("state", "ESTABLISHED"))
        if not router_id or state not in ("PENDING", "ESTABLISHED", "OVERLAP"):
            return None
        result = dict(entry)
        result.update({"vip": _canonical_ipv6(vip, "vIP"), "router_id": router_id,
                       "original_ip": original_ip, "originalIP": original_ip,
                       "source_token": token, "record_type": record_type,
                       "state": state, "expires_at": expires_at})
        return result
    except (KeyError, TypeError, ValueError):
        return None


def expire(now=None):
    now = time.time() if now is None else float(now)
    with _LOCK:
        state = _load()
        cleaned = {}
        for vip, entry in state.items():
            normalized = _normalized_entry(vip, entry, now)
            if normalized is not None:
                cleaned[normalized["vip"]] = normalized
        if cleaned != state:
            _save(cleaned)
        return cleaned


def entries(now=None):
    """Return a snapshot of non-expired table records."""
    return dict(expire(now))


def get(vip):
    try:
        key = _canonical_ipv6(vip, "vIP")
    except ValueError:
        return None
    return expire().get(key)


def get_by_original_ip(original_ip, *, authenticated_only=True):
    """Return rows for an originalIP; pending vIPs are excluded by default."""
    key = _canonical_ipv6(original_ip, "original IP")
    return [
        entry for entry in expire().values()
        if entry["original_ip"] == key
        and (not authenticated_only or entry.get("authenticated") is True)
    ]


def get_by_source_token(source_token):
    key = _canonical_ipv6(source_token, "SourceToken")
    return [entry for entry in expire().values() if entry["source_token"] == key]


def reserve(vip, router_id, original_ip, identity_public_key, *,
            source_token=None, session_id=None, expires_at=None, state="PENDING"):
    """Reserve a bootstrap vIP before it can enter the accepted LSDB."""
    vip = _canonical_ipv6(vip, "vIP")
    original_ip = _canonical_ipv6(original_ip, "original IP")
    source_token = _canonical_ipv6(source_token or vip, "SourceToken")
    if not router_id or not identity_public_key:
        raise ValueError("router identity and public key are required")
    if state not in ("PENDING", "ESTABLISHED", "OVERLAP"):
        raise ValueError("invalid vIP table state")
    deadline = float(expires_at if expires_at is not None else time.time() + 10.0)
    if deadline <= time.time():
        raise ValueError("vIP reservation expiry must be in the future")
    with _LOCK:
        current = expire()
        existing = current.get(vip)
        if existing and (existing.get("router_id") != str(router_id)
                         or existing.get("original_ip") != original_ip
                         or existing.get("session_id") != session_id):
            raise ValueError("vIP collision with an existing reservation")
        for other_vip, entry in current.items():
            if other_vip != vip and (
                entry.get("source_token") == source_token
                or (entry.get("original_ip") == original_ip
                    and entry.get("router_id") != str(router_id))
            ):
                raise ValueError("vIP/SourceToken table collision")
        entry = {
            "router_id": str(router_id),
            "original_ip": original_ip,
            "identity_public_key": str(identity_public_key),
            "source_token": source_token,
            "session_id": session_id.hex() if isinstance(session_id, bytes) else session_id,
            "state": state,
            "expires_at": deadline,
            "updated_at": time.time(),
        }
        current[vip] = entry
        _save(current)
        return dict(entry, vip=vip)


def publish_authenticated(vip, router_id, original_ip, identity_public_key, *,
                          source_token, session_id, record_seq=0,
                          expires_at=None, state="ESTABLISHED",
                          send_token=None, local_original_ip=None):
    """Publish originalIP into the LSDB only after authenticated handshake success."""
    if state not in ("ESTABLISHED", "OVERLAP"):
        raise ValueError("only authenticated established sessions may be published")
    vip = _canonical_ipv6(vip, "vIP")
    original_ip = _canonical_ipv6(original_ip, "original IP")
    source_token = _canonical_ipv6(source_token, "SourceToken")
    if not router_id or not identity_public_key:
        raise ValueError("router identity and public key are required")
    session_hex = session_id.hex() if isinstance(session_id, bytes) else str(session_id or "")
    if not session_hex or session_hex == "None":
        raise ValueError("session_id is required for authenticated vIP publication")
    deadline = float(expires_at if expires_at is not None else time.time() + _DEFAULT_TTL)
    if deadline <= time.time():
        raise ValueError("LSDB expiry must be in the future")
    with _LOCK:
        current = expire()
        for other_vip, entry in current.items():
            if other_vip == vip:
                continue
            # A router's two directions share the same router originalIP but
            # have different SourceTokens; both rows describe the same session.
            if entry.get("source_token") == source_token:
                raise ValueError("SourceToken already belongs to another vIP")
            if entry.get("original_ip") == original_ip and entry.get("router_id") != str(router_id):
                raise ValueError("original IP already belongs to another router")
            # Same-router duplicate originalIP rows are valid during make-before-break
            # rekey. The LSDB keeps both session-specific SourceTokens until overlap
            # cleanup removes the retired session's entries.
        old = current.get(vip)
        if old and (
            old.get("router_id") != str(router_id)
            or old.get("session_id") != session_hex
        ):
            raise ValueError("vIP already belongs to another router/session")
        if old and old.get("record_type") == "bootstrap_vip":
            raise ValueError("bootstrap vIP must be retired before SourceToken publication")
        if old and old.get("authenticated") is True and (
            old.get("original_ip") != original_ip
            or old.get("source_token") != source_token
            or old.get("identity_public_key") != str(identity_public_key)
            or old.get("send_token") != (
                _canonical_ipv6(send_token, "send SourceToken") if send_token else None
            )
            or old.get("local_original_ip") != (
                _canonical_ipv6(local_original_ip, "local original IP") if local_original_ip else None
            )
        ):
            raise ValueError("authenticated vIP binding is immutable within a session")
        current[vip] = {
            "router_id": str(router_id),
            "original_ip": original_ip,
            "originalIP": original_ip,
            "identity_public_key": str(identity_public_key),
            "source_token": source_token,
            "send_token": _canonical_ipv6(send_token, "send SourceToken") if send_token else None,
            "local_original_ip": _canonical_ipv6(local_original_ip, "local original IP") if local_original_ip else None,
            "session_id": session_hex,
            "record_seq": int(record_seq),
            "state": state,
            "authenticated": True,
            "expires_at": deadline,
            "updated_at": time.time(),
        }
        _save(current)
        return dict(current[vip], vip=vip)


def upsert(vip, router_id, original_ip, identity_public_key, expires_at,
           *, source_token=None, session_id=None, record_seq=0, state="ESTABLISHED"):
    """Compatibility alias for authenticated publication; callers must be trusted."""
    if not session_id:
        raise ValueError("session_id is required for LSDB publication")
    return publish_authenticated(
        vip, router_id, original_ip, identity_public_key,
        source_token=source_token or vip, session_id=session_id,
        record_seq=record_seq, expires_at=expires_at, state=state,
    )


def set_state(vip, state, *, expires_at=None):
    if state not in ("PENDING", "ESTABLISHED", "OVERLAP"):
        raise ValueError("invalid vIP table state")
    key = _canonical_ipv6(vip, "vIP")
    with _LOCK:
        current = expire()
        entry = current.get(key)
        if entry is None:
            raise KeyError("vIP is not present in NLS table")
        if state == "ESTABLISHED" and entry.get("authenticated") is not True:
            raise ValueError("cannot promote an unauthenticated vIP record")
        entry["state"] = state
        if expires_at is not None:
            deadline = float(expires_at)
            if deadline <= time.time():
                raise ValueError("LSDB expiry must be in the future")
            entry["expires_at"] = deadline
        entry["updated_at"] = time.time()
        _save(current)
        return dict(entry, vip=key)


def remove(vip, *, session_id=None):
    try:
        key = _canonical_ipv6(vip, "vIP")
    except ValueError:
        return False
    with _LOCK:
        current = _load()
        # Legacy unversioned files are maps directly keyed by vIP.
        entries = current.get("entries") if current.get("_table_version") == TABLE_VERSION else current
        if not isinstance(entries, dict):
            raise RuntimeError("NLS vIP/LSDB state is invalid")
        existing = entries.get(key)
        if existing is None:
            return False
        expected_session = session_id.hex() if isinstance(session_id, bytes) else session_id
        if expected_session is not None and existing.get("session_id") != expected_session:
            return False
        entries.pop(key, None)
        _save(entries)
        return True


def publish_bootstrap_vip(vip, router_id, original_ip, identity_public_key, *,
                          session_id, expires_at, record_seq=0):
    """Publish a pending bootstrap vIP reservation; never grants peer reachability."""
    vip = _canonical_ipv6(vip, "vIP")
    original_ip = _canonical_ipv6(original_ip, "original IP")
    if not router_id or not identity_public_key:
        raise ValueError("router identity and public key are required")
    session_hex = session_id.hex() if isinstance(session_id, bytes) else str(session_id or "")
    if not session_hex or session_hex == "None":
        raise ValueError("session_id is required for bootstrap vIP")
    deadline = float(expires_at)
    if deadline <= time.time():
        raise ValueError("bootstrap vIP expiry must be in the future")
    with _LOCK:
        current = expire()
        old = current.get(vip)
        if old and (
            old.get("session_id") != session_hex
            or old.get("router_id") != str(router_id)
            or old.get("record_type") != "bootstrap_vip"
        ):
            raise ValueError("bootstrap vIP collision")
        if old and (
            old.get("original_ip") != original_ip
            or old.get("identity_public_key") != str(identity_public_key)
        ):
            raise ValueError("bootstrap vIP binding is immutable within a session")
        for other_vip, entry in current.items():
            if other_vip != vip and (
                entry.get("original_ip") == original_ip
                and entry.get("router_id") != str(router_id)
            ):
                raise ValueError("original IP already belongs to another router")
        current[vip] = {
            "record_type": "bootstrap_vip",
            "router_id": str(router_id),
            "original_ip": original_ip,
            "originalIP": original_ip,
            "identity_public_key": str(identity_public_key),
            "source_token": None,
            "send_token": None,
            "local_original_ip": None,
            "session_id": session_hex,
            "record_seq": int(record_seq),
            "state": "PENDING",
            "authenticated": False,
            "expires_at": deadline,
            "updated_at": time.time(),
        }
        _save(current)
        return dict(current[vip], vip=vip)


def publish_authenticated_vip(vip, router_id, original_ip, identity_public_key, *,
                              source_token, session_id, record_seq=0,
                              expires_at=None, state="ESTABLISHED",
                              send_token=None, local_original_ip=None):
    """Publish a validated router originalIP -> active SourceToken binding."""
    return publish_authenticated(
        vip, router_id, original_ip, identity_public_key,
        source_token=source_token, session_id=session_id, record_seq=record_seq,
        expires_at=expires_at, state=state, send_token=send_token,
        local_original_ip=local_original_ip,
    )


def get_by_router_id(router_id, *, authenticated_only=True):
    """Return unexpired vIP/SourceToken rows for a router identity."""
    if not isinstance(router_id, str) or not router_id:
        raise ValueError("router_id is required")
    return [
        dict(entry) for entry in expire().values()
        if entry.get("router_id") == router_id
        and (not authenticated_only or entry.get("authenticated") is True)
    ]


def resolve_original_ip(original_ip, *, authenticated_only=True):
    """Resolve a router originalIP to its current authenticated SourceToken row."""
    key = _canonical_ipv6(original_ip, "original IP")
    matches = [
        dict(entry) for entry in expire().values()
        if entry.get("original_ip") == key
        and (not authenticated_only or entry.get("authenticated") is True)
        and entry.get("state") in ("ESTABLISHED", "OVERLAP")
    ]
    if not matches:
        return None
    # During make-before-break rekey, an originalIP may temporarily have both
    # old and new session tokens. Prefer ESTABLISHED, then the newest row, so
    # forwarding lookups switch to the new authenticated session while OVERLAP
    # remains available to receive in-flight packets.
    return max(matches, key=lambda entry: (
        entry.get("state") == "ESTABLISHED",
        float(entry.get("updated_at", 0)),
        int(entry.get("record_seq", 0)),
    ))
