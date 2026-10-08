"""Ephemeral NLS trust LSDB: temporary vIP to authenticated original-IP bindings."""
from __future__ import annotations
import json
import os
import time
from pathlib import Path

STATE_PATH = Path(os.environ.get("NLSXNETOS_NLS_LSDB", "/run/nlsxnetos/nls-lsdb.json"))

def _load():
    if not STATE_PATH.exists():
        return {}
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}

def _save(value):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o640)
    tmp.replace(STATE_PATH)

def expire(now=None):
    now = time.time() if now is None else float(now)
    state = _load()
    changed = False
    for vip, entry in list(state.items()):
        if float(entry.get("expires_at", 0)) <= now:
            state.pop(vip, None)
            changed = True
    if changed:
        _save(state)
    return state

def upsert(vip, router_id, original_ip, identity_public_key, expires_at):
    if not vip or not original_ip:
        raise ValueError("vIP and original IP are required")
    state = expire()
    state[str(vip)] = {
        "router_id": str(router_id),
        "original_ip": str(original_ip),
        "identity_public_key": str(identity_public_key),
        "expires_at": float(expires_at),
    }
    _save(state)
    return state[str(vip)]

def remove(vip):
    state = _load()
    if str(vip) in state:
        state.pop(str(vip), None)
        _save(state)

def get(vip):
    return expire().get(str(vip))
