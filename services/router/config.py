from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from pathlib import Path

import yaml

from kernel.config import CONFIG_DIR

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
            "nls_routes": [],
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
    root.setdefault("nls_routes", [])
    if not isinstance(root["nls_routes"], list):
        raise ValueError("router.nls_routes must be a list")
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


def validate_nls_route(
    prefix: str,
    router_id: str,
    existing: list[dict] | None = None,
    *,
    local_prefixes: list[str] | None = None,
    known_router_ids: set[str] | None = None,
    expected_family: int | None = None,
) -> dict:
    """Validate an operator-owned NLS route; no default/local/overlapping prefixes.

    Callers with a verified Router Directory must pass known_router_ids and the
    router's CA-authorized endpoint family. This pure validator never queries
    or mutates the kernel route table.
    """
    network = ipaddress.ip_network(str(prefix), strict=True)
    if network.prefixlen == 0:
        raise ValueError("NLS default routes are prohibited")
    if expected_family is not None and network.version != expected_family:
        raise ValueError("NLS route address-family mismatch")
    if not isinstance(router_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", router_id):
        raise ValueError("invalid NLS router ID")
    if known_router_ids is not None and router_id not in known_router_ids:
        raise ValueError("unknown NLS router ID")
    for local_prefix in local_prefixes or []:
        try:
            local = ipaddress.ip_network(str(local_prefix), strict=False)
        except (ValueError, TypeError) as exc:
            raise ValueError("local prefix configuration is invalid") from exc
        if network.version == local.version and network.overlaps(local):
            raise ValueError(f"NLS route {network} overlaps local prefix {local}")
    for item in existing or []:
        try:
            old = ipaddress.ip_network(item["prefix"], strict=True)
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError("existing NLS route configuration is invalid") from exc
        if network.version == old.version and network.overlaps(old):
            raise ValueError(f"NLS route {network} overlaps configured route {old}")
    return {"prefix": str(network), "router_id": router_id}


def add_nls_route(data: dict, prefix: str, router_id: str, **validation) -> dict:
    root = data.setdefault("router", _default()["router"])
    routes = root.setdefault("nls_routes", [])
    route = validate_nls_route(prefix, router_id, routes, **validation)
    routes.append(route)
    return route


def remove_nls_route(data: dict, prefix: str) -> bool:
    network = ipaddress.ip_network(str(prefix), strict=True)
    root = data.setdefault("router", _default()["router"])
    routes = root.setdefault("nls_routes", [])
    for index, item in enumerate(routes):
        if ipaddress.ip_network(item["prefix"], strict=True) == network:
            del routes[index]
            return True
    return False
