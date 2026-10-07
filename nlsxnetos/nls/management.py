from __future__ import annotations

import os
import subprocess
import yaml

from nlsxnetos.core.config import CONFIG_DIR

CONFIG_PATH = CONFIG_DIR / "nls.yaml"


def _load_raw():
    if CONFIG_PATH.exists():
        data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("NLS configuration must be a YAML mapping")
        data.setdefault("nls", {})
        return data
    return {"nls": {}}


def _save_raw(data):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    os.chmod(tmp, 0o640)
    tmp.replace(CONFIG_PATH)


def update(**values):
    data = _load_raw()
    nls = data["nls"]
    for key, value in values.items():
        if value is None:
            nls.pop(key, None)
        else:
            nls[key] = value
    _save_raw(data)


def set_enabled(enabled: bool):
    if enabled:
        data = _load_raw()
        tun = data["nls"].setdefault("tun", {})
        tun["enabled"] = True
        _save_raw(data)
    update(enabled=bool(enabled))
    service = "nls-router.service"
    subprocess.run(["systemctl", "enable" if enabled else "disable", service], check=False)
    subprocess.run(["systemctl", "restart" if enabled else "stop", service], check=False)


def erase():
    """Disable NLS and remove only the NLS runtime configuration.

    Router interfaces, FRR configuration, router identity keys, and the Ubuntu
    system are deliberately left untouched.
    """
    subprocess.run(["systemctl", "disable", "--now", "nls-router.service"], check=False)
    data = _load_raw()
    defaults = {
        "enabled": False,
        "router_ca": {
            "server_url": "",
            "ca_file": "",
            "timeout_seconds": 5,
            "bearer_token": "",
        },
        "router_id": "nls-router",
        "advertised_endpoint": "",
        "identity_key": "/var/lib/nlsxnetos/identity/ed25519.key",
        "encryption_private_key": "/var/lib/nlsxnetos/identity/rsa-encryption.pem",
        "listen_address": "::",
        "listen_port": 4789,
        "bind_interface": "",
        "replay_window": 64,
        "max_clock_skew_seconds": 120,
        "session_timeout_seconds": 300,
        "peer_block_seconds": 60,
        "auto_router_ca": True,
        "tun": {"enabled": False, "name": "nls0", "mtu": 1280},
        "peers": [],
    }
    data["nls"] = defaults
    _save_raw(data)
    return True


def status():
    return _load_raw().get("nls", {})
