"""Temporary NLS vIP trust table.

This is the NLS security/routing state used for vIP lifetime. It is deliberately
separate from FRR's OSPF LSDB; FRR LSAs are not modified by the NLS daemon.
"""
import json
import os
import time
from pathlib import Path

STATE_PATH = Path(os.environ.get("NLSXNETOS_VIP_LSDB", "/run/nlsxnetos/vip-lsdb.json"))

def _load():
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

def _save(data):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp=STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o640)
    tmp.replace(STATE_PATH)

def install(vip_token, vip_address, router_id, original_ip, expires_at):
    data=_load()
    data[vip_token]={
        "vip_address":vip_address,"router_id":router_id,
        "original_ip":original_ip,"expires_at":int(expires_at)
    }
    _save(data)

def remove(vip_token):
    data=_load()
    data.pop(vip_token,None)
    _save(data)

def expire(now=None):
    now=int(time.time() if now is None else now)
    data=_load()
    changed=False
    for token,item in list(data.items()):
        if int(item.get("expires_at",0)) <= now:
            data.pop(token,None); changed=True
    if changed:
        _save(data)
    return data
