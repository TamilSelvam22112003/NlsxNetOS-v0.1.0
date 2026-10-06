from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

import yaml

from nlsxnetos.core.config import CONFIG_DIR

PATH = CONFIG_DIR / "router.yaml"
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_CISCO_IFACE_RE = re.compile(r"^(?:g|gi|gig|gigabit|gigabitethernet)(\d+)/(\d+)$", re.IGNORECASE)


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
    tmp.replace(PATH)


def _linux_interfaces() -> list[str]:
    net = Path("/sys/class/net")
    if not net.exists():
        return []
    return sorted(
        p.name for p in net.iterdir()
        if p.name != "lo" and p.is_dir()
    )


def normalize_interface_name(name: str) -> str:
    """Accept Cisco-style g0/0 and common Linux interface names."""
    match = _CISCO_IFACE_RE.fullmatch(name.strip())
    if not match:
        return name.strip()
    slot, port = match.groups()
    if slot != "0":
        raise ValueError("only g0/<port> is supported for the initial NlsxNetOS chassis")
    return f"g0/{int(port)}"


def resolve_interface(name: str, data: dict | None = None) -> str:
    """Resolve a Cisco-facing interface name to a Linux netdev.

    The mapping is persisted in router.yaml once an interface is configured.
    For a fresh configuration, g0/N maps to the Nth non-loopback NIC.
    """
    logical = normalize_interface_name(name)
    if not _CISCO_IFACE_RE.fullmatch(logical):
        validate_linux_interface(logical)
        return logical

    configured = ((data or load()).get("router", {}).get("interfaces", {}) or {}).get(logical, {})
    linux_name = configured.get("linux_name")
    if linux_name:
        validate_linux_interface(linux_name)
        return linux_name

    port = int(logical.split("/")[1])
    available = _linux_interfaces()
    if port >= len(available):
        raise ValueError(
            f"{logical} is not available: detected non-loopback interfaces are "
            + (", ".join(available) if available else "none")
        )
    return available[port]


def validate_linux_interface(name: str) -> None:
    if not _IFACE_RE.fullmatch(name) or len(name) > 64:
        raise ValueError("invalid Linux interface name")
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


def validate_interface(name: str, data: dict | None = None) -> None:
    resolve_interface(name, data)


def set_address(interface: str, address: str, data: dict | None = None) -> None:
    linux_name = resolve_interface(interface, data)
    network = ipaddress.ip_interface(address)
    result = subprocess.run(
        ["ip", "address", "show", "dev", linux_name],
        check=True,
        capture_output=True,
        text=True,
    )
    if str(network) not in result.stdout:
        subprocess.run(
            ["ip", "address", "add", str(network), "dev", linux_name],
            check=True,
        )


def remove_address(interface: str, address: str, data: dict | None = None) -> None:
    linux_name = resolve_interface(interface, data)
    network = ipaddress.ip_interface(address)
    subprocess.run(
        ["ip", "address", "del", str(network), "dev", linux_name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def set_link(interface: str, enabled: bool, data: dict | None = None) -> None:
    linux_name = resolve_interface(interface, data)
    subprocess.run(
        ["ip", "link", "set", "dev", linux_name, "up" if enabled else "down"],
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
    logical = normalize_interface_name(interface)
    linux_name = resolve_interface(logical, data)
    entry = data["router"]["interfaces"].setdefault(
        logical,
        {
            "linux_name": linux_name,
            "addresses": [],
            "nls_role": None,
            "enabled": False,
        },
    )
    entry["linux_name"] = linux_name
    if address is not None and address not in entry["addresses"]:
        entry["addresses"].append(address)
    if role is not None:
        entry["nls_role"] = role
    if enabled is not None:
        entry["enabled"] = enabled


def configured_linux_name(logical: str, data: dict | None = None) -> str:
    return resolve_interface(logical, data)
