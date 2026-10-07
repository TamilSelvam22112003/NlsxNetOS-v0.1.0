from __future__ import annotations

from nlsxnetos.nls import management


def configure(**kwargs):
    values = {}
    for key, value in kwargs.items():
        if value is not None:
            values[key] = value
    if values:
        management.update(**values)


def status():
    data = management.status()
    ca = data.get("router_ca", {}) or {}
    print("NLS enabled:", bool(data.get("enabled", False)))
    print("Router ID:", data.get("router_id", "nls-router"))
    print("Router-CA server:", ca.get("server_url") or "not configured")
    print("Router-CA CA file:", ca.get("ca_file") or "system trust store")
    print("Bind interface:", data.get("bind_interface") or "kernel routing")
    print("UDP:", f"{data.get('listen_address', '::')}:{data.get('listen_port', 4789)}")
    tun = data.get("tun", {}) or {}
    print("TUN:", tun.get("name", "nls0"), "enabled=", bool(tun.get("enabled", False)), "mtu=", tun.get("mtu", 1280))


def enable():
    management.set_enabled(True)
    print("NLS enabled.")


def disable():
    management.set_enabled(False)
    print("NLS disabled.")


def erase():
    management.erase()
    print("NLS configuration erased. Router interfaces and FRR configuration were not changed.")
