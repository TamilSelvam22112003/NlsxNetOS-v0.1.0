from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from pathlib import Path

import yaml

from nlsxnetos.core.config import CONFIG_DIR

PATH = CONFIG_DIR / "router.yaml"
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _default() -> dict:
    return {
        "router": {
            "enabled": False,
            "ipv4_forwarding": False,
            "ipv6_forwarding": False,
            "frr_service": "frr",
            "interfaces": {},
        }
    }


def load() -> dict:
    if not PATH.exists():
        return _default()
    data = yaml.safe_load(PATH.read_text(encoding="utf-8")) or {}
    root = data.setdefault("router", {})
    root.setdefault("enabled", False)
    root.setdefault("ipv4_forwarding", False)
    root.setdefault("ipv6_forwarding", False)
    root.setdefault("frr_service", "frr")
    root.setdefault("interfaces", {})
    return data


def save(data: dict) -> None:
    PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PATH.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    os.chmod(tmp, 0o640)
    tmp.replace(PATH)
    try:
        import grp
        os.chown(PATH, -1, grp.getgrnam("nlsxnetos").gr_gid)
    except (KeyError, PermissionError):
        pass


def validate_interface(name: str) -> None:
    if not _IFACE_RE.fullmatch(name) or len(name) > 64:
        raise ValueError("invalid interface name")
    try:
        subprocess.run(
            ["ip", "link", "show", "dev", name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("ip command is not installed") from exc
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"interface {name!r} does not exist") from exc


def set_address(interface: str, address: str) -> None:
    validate_interface(interface)
    network = ipaddress.ip_interface(address)
    result = subprocess.run(
        ["ip", "address", "show", "dev", interface],
        check=True,
        capture_output=True,
        text=True,
    )
    if str(network) not in result.stdout:
        subprocess.run(
            ["ip", "address", "add", str(network), "dev", interface],
            check=True,
        )


def remove_address(interface: str, address: str) -> None:
    validate_interface(interface)
    network = ipaddress.ip_interface(address)
    subprocess.run(
        ["ip", "address", "del", str(network), "dev", interface],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def set_link(interface: str, enabled: bool) -> None:
    validate_interface(interface)
    subprocess.run(
        ["ip", "link", "set", "dev", interface, "up" if enabled else "down"],
        check=True,
    )


def record_interface(
    data: dict,
    interface: str,
    *,
    address: str | None = None,
    role: str | None = None,
    enabled: bool | None = None,
) -> None:
    entry = data["router"]["interfaces"].setdefault(
        interface, {"addresses": [], "nls_role": None, "enabled": False}
    )
    if address is not None and address not in entry["addresses"]:
        entry["addresses"].append(address)
    if role is not None:
        entry["nls_role"] = role
    if enabled is not None:
        entry["enabled"] = enabled
