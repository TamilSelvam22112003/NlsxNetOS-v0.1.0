"""NLS Trust Table containing only Router-CA cross-verified peer bindings."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


STATE_PATH = Path(
    os.environ.get("NLSXNETOS_TRUST_TABLE", "/var/lib/nlsxnetos/nls-trust-table.json")
)


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
    for peer_id, entry in list(state.items()):
        if float(entry.get("expires_at", 0)) <= now:
            state.pop(peer_id, None)
            changed = True
    if changed:
        _save(state)
    return state


def upsert(peer_id, router_ca_details, router_details, expires_at):
    """Record a trust decision after exact Router-CA/peer-detail comparison."""
    if not peer_id or not isinstance(router_ca_details, dict) or not isinstance(router_details, dict):
        raise ValueError("peer identity and both verified detail records are required")
    state = expire()
    entry = {
        "router_ca_details": dict(router_ca_details),
        "router_details": dict(router_details),
        "verified_at": time.time(),
        "expires_at": float(expires_at),
    }
    state[str(peer_id)] = entry
    _save(state)
    return entry


def get(peer_id):
    return expire().get(str(peer_id))


def remove(peer_id):
    state = _load()
    if str(peer_id) in state:
        state.pop(str(peer_id), None)
        _save(state)
