from __future__ import annotations

import subprocess
from pathlib import Path

from nlsxnetos import router_config


def _sysctl(name, value):
    Path(f"/proc/sys/{name.replace('.', '/')}").write_text(str(int(value)), encoding="ascii")


def _service(action, service):
    subprocess.run(["systemctl", action, service], check=False)


def apply(data=None, start_frr=True):
    data = data or router_config.load()
    cfg = data["router"]
    enabled = bool(cfg.get("enabled", False))
    _sysctl("net.ipv4.ip_forward", enabled and bool(cfg.get("ipv4_forwarding", False)))
    _sysctl("net.ipv6.conf.all.forwarding", enabled and bool(cfg.get("ipv6_forwarding", False)))

    for name, iface in cfg.get("interfaces", {}).items():
        if not iface.get("enabled", False):
            continue
        router_config.validate_interface(name)
        subprocess.run(["ip", "link", "set", "dev", name, "up"], check=True)
        for address in iface.get("addresses", []):
            router_config.set_address(name, address)

    if enabled and start_frr:
        _service("enable", cfg.get("frr_service", "frr"))
        _service("start", cfg.get("frr_service", "frr"))
    return cfg


def enable():
    data = router_config.load()
    cfg = data["router"]
    cfg["enabled"] = True
    cfg["ipv4_forwarding"] = True
    cfg["ipv6_forwarding"] = True
    router_config.save(data)
    return apply(data)


def disable():
    data = router_config.load()
    cfg = data["router"]
    cfg["enabled"] = False
    cfg["ipv4_forwarding"] = False
    cfg["ipv6_forwarding"] = False
    router_config.save(data)
    return apply(data, start_frr=False)


def status():
    data = router_config.load()["router"]
    return data
