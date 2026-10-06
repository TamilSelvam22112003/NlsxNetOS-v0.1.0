import base64
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


pytestmark = pytest.mark.integration

ROUTERS = [f"nls-r{i}" for i in range(1, 11)]
LINKS = [
    (1, "fd00:100:1::1", "fd00:100:1::2"),
    (2, "fd00:100:2::1", "fd00:100:2::2"),
    (3, "fd00:100:3::1", "fd00:100:3::2"),
    (4, "fd00:100:4::1", "fd00:100:4::2"),
    (5, "fd00:100:5::1", "fd00:100:5::2"),
    (6, "fd00:100:6::1", "fd00:100:6::2"),
    (7, "fd00:100:7::1", "fd00:100:7::2"),
    (8, "fd00:100:8::1", "fd00:100:8::2"),
    (9, "fd00:100:9::1", "fd00:100:9::2"),
]

R1_NLS_ENDPOINT = "fd00:100:1::1"
R10_NLS_ENDPOINT = "fd00:100:9::2"
R1_REQUESTED_ADDRESS = "fd00:1234:5678:a1b2::1"
R10_REQUESTED_ADDRESS = "fe80::c0a8:101"
TEMP_ROUTER_CA_ADDRESS = "2001:4860:4860::8888"
CLIENT_IP = "fd00:200::10"
SERVER_IP = "fd00:300::10"


def run(*args, ns=None, check=True, timeout=15):
    cmd = ["ip", "netns", "exec", ns, *args] if ns else list(args)
    return subprocess.run(cmd, check=check, text=True, capture_output=True, timeout=timeout)


def ns_exec(ns, *args, check=True, timeout=15):
    return run(*args, ns=ns, check=check, timeout=timeout)


def add_veth(ns_a, if_a, ns_b, if_b):
    host_a = (ns_a + "-" + if_a + "-a")[:15]
    host_b = (ns_b + "-" + if_b + "-b")[:15]
    run("ip", "link", "add", host_a, "type", "veth", "peer", "name", host_b)
    run("ip", "link", "set", host_a, "netns", ns_a)
    run("ip", "link", "set", host_b, "netns", ns_b)
    ns_exec(ns_a, "ip", "link", "set", host_a, "name", if_a)
    ns_exec(ns_b, "ip", "link", "set", host_b, "name", if_b)
    ns_exec(ns_a, "ip", "link", "set", if_a, "up")
    ns_exec(ns_b, "ip", "link", "set", if_b, "up")


def add_addr(ns, interface, address):
    ns_exec(ns, "ip", "-6", "addr", "add", address, "dev", interface)


def add_route(ns, destination, via=None, dev=None):
    cmd = ["ip", "-6", "route", "add", destination]
    if via:
        cmd += ["via", via]
    if dev:
        cmd += ["dev", dev]
    ns_exec(ns, *cmd)


def generate_identity():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return private, public


def write_config(root, router_id, endpoint, bind_interface, identity_path, entries):
    etc = root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    config = {
        "nls": {
            "enabled": True,
            "auto_router_ca": True,
            "protocol_version": 1,
            "router_id": router_id,
            "identity_key": str(identity_path),
            "listen_address": endpoint,
            "listen_port": 4789,
            "bind_interface": bind_interface,
            "replay_window": 64,
            "max_clock_skew_seconds": 120,
            "session_timeout_seconds": 60,
            "peer_block_seconds": 5,
            "tun": {"enabled": True, "name": "nls0", "mtu": 1280},
            "peers": [],
        }
    }
    (etc / "nls.yaml").write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    (etc / "router-ca.yaml").write_text(
        yaml.safe_dump({"entries": entries}, sort_keys=False), encoding="utf-8"
    )


def daemon_env(root):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path.cwd())
    env["NLSXNETOS_CONFIG_DIR"] = str(root / "etc")
    env["NLSXNETOS_ROUTER_CA_PATH"] = str(root / "etc" / "router-ca.yaml")
    env["NLSXNETOS_ROUTE_STATE"] = str(root / "routes.json")
    return env


def start_daemon(ns, env):
    return subprocess.Popen(
        ["ip", "netns", "exec", ns, "python3", "-m", "nlsxnetos", "nls", "run"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def wait_ready(processes, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(p.poll() is not None for p in processes):
            break
        if all(
            ns_exec(ns, "ip", "link", "show", "nls0", check=False).returncode == 0
            for ns in ROUTERS
        ):
            return
        time.sleep(0.2)

    logs = []
    for ns, proc in zip(ROUTERS, processes):
        logs.append(f"--- {ns} rc={proc.poll()} ---")
        if proc.stdout:
            logs.append(proc.stdout.read())
    raise AssertionError("10-router NLS startup failed\n" + "\n".join(logs))


def udp_echo_server(server_ns):
    script = (
        "import socket; "
        "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); "
        f"s.bind(({SERVER_IP!r},9999)); "
        "data,addr=s.recvfrom(4096); "
        "s.sendto(b'ACK:'+data,addr)"
    )
    return subprocess.Popen(
        ["ip", "netns", "exec", server_ns, "python3", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def udp_client(client_ns, payload):
    script = (
        "import socket; "
        "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); "
        "s.bind(('fd00:200::10',0)); "
        "s.settimeout(8); "
        f"s.sendto({payload!r},({SERVER_IP!r},9999)); "
        "print(s.recvfrom(4096)[0].decode(),end='')"
    )
    return ns_exec(client_ns, "python3", "-c", script, timeout=12).stdout


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root/network namespaces")
def test_ten_router_ipv6_client_router_chain_server_and_return_path():
    namespaces = ROUTERS + ["nls-client", "nls-server"]
    processes = []

    with tempfile.TemporaryDirectory(prefix="nlsxnetos-10r-") as td:
        root = Path(td)
        try:
            for ns in namespaces:
                run("ip", "netns", "add", ns)

            # Client -> Router 1.
            add_veth("nls-client", "eth0", ROUTERS[0], "lan0")
            add_addr("nls-client", "eth0", f"{CLIENT_IP}/64")
            add_addr(ROUTERS[0], "lan0", f"{R1_REQUESTED_ADDRESS}/64")

            # Nine-router physical chain.
            for i, (_idx, left_ip, right_ip) in enumerate(LINKS):
                left = ROUTERS[i]
                right = ROUTERS[i + 1]
                left_if = "wan0" if i == 0 else "right"
                right_if = "left"
                add_veth(left, left_if, right, right_if)
                add_addr(left, left_if, f"{left_ip}/64")
                add_addr(right, right_if, f"{right_ip}/64")

            # Router 10 -> server.
            add_veth(ROUTERS[-1], "lan0", "nls-server", "eth0")
            add_addr(ROUTERS[-1], "lan0", "fd00:300::1/64")
            add_addr("nls-server", "eth0", f"{SERVER_IP}/64")

            # Exact requested Router-10 address.
            add_addr(ROUTERS[-1], "lan0", f"{R10_REQUESTED_ADDRESS}/64")

            # Exact requested temporary Router-CA address, kept local to Router 5.
            ns_exec(
                ROUTERS[4],
                "ip", "-6", "addr", "add",
                f"{TEMP_ROUTER_CA_ADDRESS}/128", "dev", "lo",
            )

            for ns in ROUTERS:
                ns_exec(ns, "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")

            # Client/server ordinary routing.
            add_route(
                "nls-client", "default",
                via=R1_REQUESTED_ADDRESS, dev="eth0"
            )
            add_route(
                "nls-server", "default",
                via="fd00:300::1", dev="eth0"
            )

            # Outer NLS transport endpoint routing through all intermediate routers.
            # R1 -> R10.
            for i in range(1, 9):
                current = ROUTERS[i - 1]
                next_hop = f"fd00:100:{i}::2"
                dev = "wan0" if i == 1 else "right"
                add_route(current, f"{R10_NLS_ENDPOINT}/128", via=next_hop, dev=dev)

            # R10 -> R1.
            for i in range(9, 1, -1):
                current = ROUTERS[i - 1]
                next_hop = f"fd00:100:{i-1}::1"
                add_route(current, f"{R1_NLS_ENDPOINT}/128", via=next_hop, dev="left")

            identities = {}
            for i, ns in enumerate(ROUTERS, 1):
                private, public = generate_identity()
                identities[i] = {"private": private, "public": public}
                path = root / ns / "state" / "identity"
                path.mkdir(parents=True)
                (path / "ed25519.key").write_bytes(private)

            for i, ns in enumerate(ROUTERS, 1):
                rroot = root / ns
                identity_path = rroot / "state" / "identity" / "ed25519.key"

                if i == 1:
                    endpoint = R1_NLS_ENDPOINT
                    bind = "wan0"
                    entries = [{
                        "id": 10,
                        "prefix": "fd00:300::/64",
                        "label": "router-10-server",
                        "public_key": identities[10]["public"],
                        "endpoint": f"[{R10_NLS_ENDPOINT}]:4789",
                    }]
                elif i == 10:
                    endpoint = R10_NLS_ENDPOINT
                    bind = "left"
                    entries = [{
                        "id": 1,
                        "prefix": "fd00:200::/64",
                        "label": "router-1-client",
                        "public_key": identities[1]["public"],
                        "endpoint": f"[{R1_NLS_ENDPOINT}]:4789",
                    }]
                else:
                    # All intermediate routers run NLS, but their active test
                    # Router-CA peer is deliberately unrelated to this traffic.
                    endpoint = f"fd00:100:{i}::2"
                    bind = "right"
                    entries = [{
                        "id": 1000 + i,
                        "prefix": f"fd00:9000:{i}::/64",
                        "label": f"test-peer-{i}",
                        "public_key": identities[1]["public"],
                        "endpoint": f"[{R1_NLS_ENDPOINT}]:4789",
                    }]

                write_config(
                    rroot,
                    f"router-{i}",
                    endpoint,
                    bind,
                    identity_path,
                    entries,
                )

            for i, ns in enumerate(ROUTERS, 1):
                processes.append(start_daemon(ns, daemon_env(root / ns)))

            wait_ready(processes)

            # The intermediate routers must select a physical next hop for the
            # R10 NLS endpoint. This proves they forward instead of terminating
            # the packet themselves.
            for i in range(1, 10):
                route = ns_exec(
                    ROUTERS[i - 1],
                    "ip", "-6", "route", "get", R10_NLS_ENDPOINT,
                ).stdout
                if i < 9:
                    assert f"via fd00:100:{i}::2" in route, (i, route)
                else:
                    assert "dev left" in route, (i, route)

            # Actual application traffic: client and server have no NLS config.
            server = udp_echo_server("nls-server")
            try:
                response = udp_client("nls-client", b"10-ROUTER-NLS-TEST")
                assert response == "ACK:10-ROUTER-NLS-TEST"
            finally:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()

            # Reverse path is exercised by the UDP response.
            endpoint_logs = ""
            intermediate_logs = ""
            for i, proc in enumerate(processes, 1):
                if proc.stdout:
                    text = proc.stdout.read() if proc.poll() is not None else ""
                    if i in (1, 10):
                        endpoint_logs += text
                    else:
                        intermediate_logs += text

            assert "NLS session established" in endpoint_logs
            assert "NLS DATA dropped" not in intermediate_logs
            assert "NLS session established" not in intermediate_logs

            # The requested addresses really belong to the intended machines.
            r1_addr = ns_exec(
                ROUTERS[0], "ip", "-6", "addr", "show", "dev", "lan0"
            ).stdout
            r10_addr = ns_exec(
                ROUTERS[-1], "ip", "-6", "addr", "show", "dev", "lan0"
            ).stdout
            r5_ca = ns_exec(
                ROUTERS[4], "ip", "-6", "addr", "show", "dev", "lo"
            ).stdout
            assert R1_REQUESTED_ADDRESS in r1_addr
            assert R10_REQUESTED_ADDRESS in r10_addr
            assert TEMP_ROUTER_CA_ADDRESS in r5_ca
        finally:
            for proc in processes:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGTERM)
            for proc in processes:
                try:
                    proc.wait(timeout=4)
                except Exception:
                    proc.kill()
            for ns in namespaces:
                run("ip", "netns", "del", ns, check=False)
