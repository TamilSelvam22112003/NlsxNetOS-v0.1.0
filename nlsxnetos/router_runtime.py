from __future__ import annotations

import subprocess
from pathlib import Path

from nlsxnetos import router_config

SYSCTL = {
    "ipv4_forwarding": Path("/proc/sys/net/ipv4/ip_forward"),
    "ipv6_forwarding": Path("/proc/sys/net/ipv6/conf/all/forwarding"),
}


def _sysctl(name: str, value: bool) -> None:
    path = SYSCTL[name]
    path.write_text("1\n" if value else "0\n", encoding="ascii")


def apply(*, start_frr: bool = True) -> None:
    data = router_config.load()["router"]

    if start_frr and data.get("enabled"):
        subprocess.run(
            ["systemctl", "enable", "--now", data.get("frr_service", "frr")],
            check=True,
        )

    _sysctl("ipv4_forwarding", bool(data.get("enabled") and data.get("ipv4_forwarding")))
    _sysctl("ipv6_forwarding", bool(data.get("enabled") and data.get("ipv6_forwarding")))

    for interface, cfg in data.get("interfaces", {}).items():
        router_config.validate_interface(interface)

        for address in cfg.get("addresses", []):
            router_config.set_address(interface, address)

        if "enabled" in cfg:
            router_config.set_link(interface, bool(cfg["enabled"]))


def status() -> dict:
    data = router_config.load()["router"]
    return {
        "enabled": bool(data.get("enabled")),
        "ipv4_forwarding": SYSCTL["ipv4_forwarding"].read_text(encoding="ascii").strip(),
        "ipv6_forwarding": SYSCTL["ipv6_forwarding"].read_text(encoding="ascii").strip(),
        "frr_service": data.get("frr_service", "frr"),
        "interfaces": list(data.get("interfaces", {}).keys()),
    }


def apply_saved_configuration() -> None:
    data = router_config.load()["router"]
    if not data.get("enabled"):
        return
    apply(start_frr=True)
