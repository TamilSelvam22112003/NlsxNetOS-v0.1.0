import ipaddress
import json
import os
import subprocess
from pathlib import Path


STATE_PATH = Path(os.environ.get("NLSXNETOS_ROUTE_STATE", "/run/nlsxnetos/nls-routes.json"))


def _family(address):
    return "-6" if ipaddress.ip_address(address).version == 6 else "-4"


def _run(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def _exact_route_exists(network):
    net = ipaddress.ip_network(network, strict=False)
    flag = "-6" if net.version == 6 else "-4"
    result = _run(["ip", flag, "route", "show", "exact", str(net)], check=False)
    return bool(result.stdout.strip())


def _route_get(address):
    flag = _family(address)
    result = _run(["ip", flag, "route", "get", address], check=False)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    line = result.stdout.splitlines()[0].split()
    route = {"dev": None, "via": None}
    if "dev" in line:
        route["dev"] = line[line.index("dev") + 1]
    if "via" in line:
        route["via"] = line[line.index("via") + 1]
    return route if route["dev"] else None


def _add_endpoint_host_route(endpoint, added):
    host, _ = endpoint
    address = ipaddress.ip_address(host)
    if address.version == 6 and address.is_link_local:
        return
    prefix = f"{host}/128" if address.version == 6 else f"{host}/32"
    if _exact_route_exists(prefix):
        return
    route = _route_get(host)
    if not route or not route.get("dev"):
        raise RuntimeError(f"cannot determine transport route for NLS endpoint {host}")
    flag = "-6" if address.version == 6 else "-4"
    cmd = ["ip", flag, "route", "replace", prefix]
    if route.get("via"):
        cmd += ["via", route["via"]]
    cmd += ["dev", route["dev"]]
    _run(cmd)
    added.append(prefix)


def install_tun_routes(peers, tun_name):
    """Install only missing remote-prefix routes into the NLS TUN device.

    Existing connected/static routes win. This is what makes the same daemon
    support both an NLS source router and a destination router: a destination
    LAN prefix remains on its LAN interface while remote client prefixes use NLS.
    """
    added = []
    for peer in peers:
        try:
            endpoint = _split_endpoint(peer.endpoint)
            _add_endpoint_host_route(endpoint, added)
        except Exception:
            # Endpoint pinning is best-effort; ordinary kernel routing remains valid.
            pass
        for prefix in peer.allowed_prefixes:
            network = ipaddress.ip_network(prefix, strict=False)
            if _exact_route_exists(str(network)):
                continue
            flag = "-6" if network.version == 6 else "-4"
            _run(["ip", flag, "route", "replace", str(network), "dev", tun_name])
            added.append(str(network))
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps({"routes": added, "tun": tun_name}), encoding="utf-8")
    return added


def _split_endpoint(value):
    value = str(value)
    if value.startswith("["):
        host, port = value.rsplit("]:", 1)
        return host[1:], int(port)
    host, port = value.rsplit(":", 1)
    return host, int(port)


def remove_tun_routes():
    if not STATE_PATH.exists():
        return
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {"routes": []}
    for route in data.get("routes", []):
        try:
            net = ipaddress.ip_network(route, strict=False)
            flag = "-6" if net.version == 6 else "-4"
            _run(["ip", flag, "route", "del", str(net)], check=False)
        except ValueError:
            continue
    try:
        STATE_PATH.unlink()
    except FileNotFoundError:
        pass
