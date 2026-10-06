import base64
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


pytestmark = pytest.mark.integration


ROUTERS = [
    ("r1", "fd00:1234:5678:a1b2::1", "fd00:1234:1::1"),
    ("r2", "fd00:1234:2::1", "fd00:1234:2::2"),
    ("r3", "fd00:1234:3::1", "fd00:1234:3::2"),
    ("r4", "fd00:1234:4::1", "fd00:1234:4::2"),
    ("r5", "fd00:1234:5::1", "fd00:1234:5::2"),
    ("r6", "fd00:1234:6::1", "fd00:1234:6::2"),
    ("r7", "fd00:1234:7::1", "fd00:1234:7::2"),
    ("r8", "fd00:1234:8::1", "fd00:1234:8::2"),
    ("r9", "fd00:1234:9::1", "fd00:1234:9::2"),
    ("r10", "2001:4860:4860::8888", "2001:db8:10::2"),
]

LINKS = [
    ("r1", "r2", "fd00:1234:12::1", "fd00:1234:12::2"),
    ("r2", "r3", "fd00:1234:23::1", "fd00:1234:23::2"),
    ("r3", "r4", "fd00:1234:34::1", "fd00:1234:34::2"),
    ("r4", "r5", "fd00:1234:45::1", "fd00:1234:45::2"),
    ("r5", "r6", "fd00:1234:56::1", "fd00:1234:56::2"),
    ("r6", "r7", "fd00:1234:67::1", "fd00:1234:67::2"),
    ("r7", "r8", "fd00:1234:78::1", "fd00:1234:78::2"),
    ("r8", "r9", "fd00:1234:89::1", "fd00:1234:89::2"),
    ("r9", "r10", "fd00:1234:910::1", "fd00:1234:910::2"),
]


def run(*args, ns=None, check=True):
    cmd = ["ip", "netns", "exec", ns, *args] if ns else list(args)
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def ns_exec(ns, *args, check=True):
    return run(*args, ns=ns, check=check)


def add_veth(ns_a, if_a, ns_b, if_b):
    host_a = (ns_a + if_a + "a")[:15]
    host_b = (ns_b + if_b + "b")[:15]
    run("ip", "link", "add", host_a, "type", "veth", "peer", "name", host_b)
    run("ip", "link", "set", host_a, "netns", ns_a)
    run("ip", "link", "set", host_b, "netns", ns_b)
    ns_exec(ns_a, "ip", "link", "set", host_a, "name", if_a)
    ns_exec(ns_b, "ip", "link", "set", host_b, "name", if_b)
    ns_exec(ns_a, "ip", "link", "set", if_a, "up")
    ns_exec(ns_b, "ip", "link", "set", if_b, "up")


def write_router_config(root, router_id, identity_path, listen_address, bind_interface, ca_entries):
    etc = root / "etc"
    etc.mkdir(parents=True)
    root.joinpath("state/identity").mkdir(parents=True)
    (etc / "nls.yaml").write_text(
        yaml.safe_dump(
            {
                "nls": {
                    "enabled": True,
                    "auto_router_ca": True,
                    "protocol_version": 1,
                    "router_id": router_id,
                    "identity_key": str(identity_path),
                    "listen_address": listen_address,
                    "listen_port": 4789,
                    "bind_interface": bind_interface,
                    "replay_window": 64,
                    "max_clock_skew_seconds": 120,
                    "session_timeout_seconds": 60,
                    "peer_block_seconds": 5,
                    "tun": {"enabled": True, "name": "nls0", "mtu": 1280},
                    "peers": [],
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (etc / "router-ca.yaml").write_text(
        yaml.safe_dump({"entries": ca_entries}, sort_keys=False),
        encoding="utf-8",
    )


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root/network namespaces")
def test_ten_router_ipv6_chain_client_server_and_return_path():
    namespaces = [name for name, *_ in ROUTERS] + ["client", "server"]
    procs = []
    with tempfile.TemporaryDirectory(prefix="nlsxnetos-ten-router-") as td:
        root = Path(td)
        try:
            for ns in namespaces:
                run("ip", "netns", "add", ns)

            # Source router uses the requested fd00 address.
            add_veth("client", "c0", "r1", "lan0")
            ns_exec("client", "ip", "addr", "add", "fd00:1234:100::2/64", "dev", "c0")
            ns_exec("r1", "ip", "addr", "add", "fd00:1234:100::1/64", "dev", "lan0")

            # Nine router-to-router links.
            for i, (a, b, aa, bb) in enumerate(LINKS):
                add_veth(a, f"w{i}a", b, f"w{i}b")
                ns_exec(a, "ip", "addr", "add", f"{aa}/64", "dev", f"w{i}a")
                ns_exec(b, "ip", "addr", "add", f"{bb}/64", "dev", f"w{i}b")

            add_veth("r10", "lan0", "server", "s0")
            ns_exec("r10", "ip", "addr", "add", "2001:db8:100::1/64", "dev", "lan0")
            ns_exec("server", "ip", "addr", "add", "2001:db8:100::2/64", "dev", "s0")

            # Requested destination-router identity is the r10 address.
            # The requested Router-CA test address is also installed on r10.
            ns_exec("r10", "ip", "addr", "add", "2001:4860:4860::8888/128", "dev", "lan0")

            # Requested link-local destination-router address is installed on r1's
            # source-facing WAN interface. It is scoped to that virtual link.
            ns_exec("r1", "ip", "addr", "add", "fe80::c0a8:101/64", "dev", "w0a")

            # Enable IPv6 forwarding on every router.
            for name, *_ in ROUTERS:
                ns_exec(name, "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")

            # Ordinary kernel reachability for the physical next hops. NLS carries
            # the end-to-end client/server prefix after Router-CA selection.
            ns_exec("client", "ip", "-6", "route", "add", "default", "via", "fd00:1234:100::1", "dev", "c0")
            ns_exec("server", "ip", "-6", "route", "add", "default", "via", "2001:db8:100::1", "dev", "s0")

            # The ten routers are a chain. Each intermediate router forwards only
            # toward the next hop when the destination prefix is not local.
            for i, (a, b, aa, bb) in enumerate(LINKS):
                ns_exec(a, "ip", "-6", "route", "add", f"fd00:1234:{i+2}::/64", "via", bb, "dev", f"w{i}a", check=False)
                ns_exec(b, "ip", "-6", "route", "add", f"fd00:1234:{i+1}::/64", "via", aa, "dev", f"w{i}b", check=False)

            keys = {}
            for name, *_ in ROUTERS:
                key = Ed25519PrivateKey.generate()
                keys[name] = key
                raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                (root / name / "state/identity").mkdir(parents=True)
                (root / name / "state/identity/ed25519.key").write_bytes(raw)

            def pub(name):
                return base64.b64encode(
                    keys[name].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                ).decode()

            # Each router trusts the next router for the next router's destination
            # prefix. r10's prefix is the server LAN.
            for idx, (name, local_ip, _peer_ip) in enumerate(ROUTERS):
                rroot = root / name
                listen = local_ip
                bind = "w0a" if name == "r1" else ("lan0" if name == "r10" else f"w{idx-1}b")
                entries = []
                if name != "r10":
                    next_name = ROUTERS[idx + 1][0]
                    endpoint = ROUTERS[idx + 1][1]
                    # The first hop is the requested link-local endpoint and is
                    # scoped through r1's WAN interface.
                    if name == "r1":
                        endpoint = "[fe80::c0a8:101]:4789"
                    entries.append(
                        {
                            "id": idx + 2,
                            "prefix": "2001:db8:100::/64",
                            "label": next_name,
                            "public_key": pub(next_name),
                            "endpoint": endpoint,
                        }
                    )
                else:
                    entries.append(
                        {
                            "id": 10,
                            "prefix": "2001:4860:4860::8888/128",
                            "label": "router-ca",
                            "public_key": pub("r10"),
                            "endpoint": "2001:db8:100::1:4789",
                        }
                    )
                write_router_config(
                    rroot,
                    name,
                    rroot / "state/identity/ed25519.key",
                    listen,
                    bind,
                    entries,
                )

            # r10's actual NLS listener is on its router-to-router link; the
            # Router-CA address is a local identity/lookup test address.
            # Normalize its local endpoint to the r9/r10 transit address.
            r10_cfg = root / "r10/etc/router-ca.yaml"
            data = yaml.safe_load(r10_cfg.read_text())
            data["entries"][0]["endpoint"] = "fd00:1234:910::2:4789"
            r10_cfg.write_text(yaml.safe_dump(data, sort_keys=False))

            for name, *_ in ROUTERS:
                env = os.environ.copy()
                env["NLSXNETOS_CONFIG_DIR"] = str(root / name / "etc")
                env["NLSXNETOS_ROUTER_CA_PATH"] = str(root / name / "etc/router-ca.yaml")
                env["NLSXNETOS_ROUTE_STATE"] = str(root / name / "routes.json")
                env["PYTHONPATH"] = str(Path.cwd())
                procs.append(
                    subprocess.Popen(
                        ["ip", "netns", "exec", name, "python3", "-m", "nlsxnetos", "nls", "run"],
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                )

            deadline = time.time() + 20
            while time.time() < deadline:
                if all(ns_exec(name, "ip", "link", "show", "nls0", check=False).returncode == 0 for name, *_ in ROUTERS):
                    break
                if any(p.poll() is not None for p in procs):
                    break
                time.sleep(0.2)
            assert all(p.poll() is None for p in procs), "one or more NLS routers exited during startup"

            # Client sends ordinary IPv6 traffic. It has no NLS configuration.
            ns_exec("client", "ping", "-6", "-c", "3", "-W", "3", "2001:db8:100::2")

            # Return path is equally automatic.
            ns_exec("server", "ping", "-6", "-c", "3", "-W", "3", "fd00:1234:100::2")
        finally:
            for p in procs:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=4)
            for ns in namespaces:
                run("ip", "netns", "del", ns, check=False)
