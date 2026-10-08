from pathlib import Path
import os
import subprocess
import yaml

from kernel.config import CONFIG_DIR
from security.trust.router_ca import store as ca_store

CONFIG_PATH = CONFIG_DIR / "nls.yaml"


def _load_raw():
    if CONFIG_PATH.exists():
        data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("NLS configuration must be a YAML mapping")
        return data
    return {"nls": {}}


def _save_raw(data):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    os.chmod(tmp, 0o640)
    tmp.replace(CONFIG_PATH)
    try:
        import grp
        os.chown(CONFIG_PATH, -1, grp.getgrnam("nlsxnetos").gr_gid)
    except (KeyError, PermissionError):
        pass


def _wan_interface():
    router_path = CONFIG_DIR / "router.yaml"
    if not router_path.exists():
        return ""
    data = yaml.safe_load(router_path.read_text(encoding="utf-8")) or {}
    for name, cfg in (data.get("router", {}).get("interfaces", {}) or {}).items():
        if cfg.get("nls_role") == "wan" and cfg.get("enabled", True):
            return name
    return ""


def activate():
    if not ca_store.active_entries():
        return False
    wan = _wan_interface()
    if not wan:
        raise RuntimeError("NLS activation requires an enabled interface with nls_role: wan")
    data = _load_raw()
    nls = data.setdefault("nls", {})
    nls["enabled"] = True
    tun = nls.setdefault("tun", {})
    tun["enabled"] = True
    tun.setdefault("name", "nls0")
    tun.setdefault("mtu", 1280)
    nls["bind_interface"] = wan
    _save_raw(data)
    try:
        subprocess.run(["systemctl", "enable", "nls-router.service"], check=False)
        subprocess.run(["systemctl", "restart", "nls-router.service"], check=False)
    except OSError:
        pass
    return True


def deactivate():
    data = _load_raw()
    nls = data.setdefault("nls", {})
    nls["enabled"] = False
    tun = nls.setdefault("tun", {})
    tun["enabled"] = False
    _save_raw(data)
    try:
        subprocess.run(["systemctl", "stop", "nls-router.service"], check=False)
    except OSError:
        pass
    return True
