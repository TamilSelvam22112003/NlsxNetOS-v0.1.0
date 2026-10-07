import base64
import ipaddress
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64
from nlsxnetos.nls.rsa_signing import public_key_b64 as rsa_signing_public_key_b64
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat


pytestmark = pytest.mark.integration


def run(*args, ns=None, check=True):
    cmd = ["ip", "netns", "exec", ns, *args] if ns else list(args)
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def ns_exec(ns, *args, check=True):
    return run(*args, ns=ns, check=check)


def make_veth(ns_a, if_a, ns_b, if_b):
    left = (ns_a + "-veth")[:15]
    right = (ns_b + "-veth")[:15]
    run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
    run("ip", "link", "set", left, "netns", ns_a)
    run("ip", "link", "set", right, "netns", ns_b)
    ns_exec(ns_a, "ip", "link", "set", left, "name", if_a)
    ns_exec(ns_b, "ip", "link", "set", right, "name", if_b)
    ns_exec(ns_a, "ip", "link", "set", if_a, "up")
    ns_exec(ns_b, "ip", "link", "set", if_b, "up")


def addr(ns, interface, value):
    ns_exec(ns, "ip", "addr", "add", value, "dev", interface)


def route(ns, *args):
    ns_exec(ns, "ip", "route", *args)


def write_config(root, router_id, listen_address, peers):
    config = root / "etc"
    state = root / "state"
    config.mkdir(parents=True)
    (state / "identity").mkdir(parents=True)
    (state / "router-ca").mkdir(parents=True)
    (config / "nls.yaml").write_text(
        """nls:
  enabled: true
  auto_router_ca: true
  protocol_version: 1
  router_id: %s
  identity_key: %s
  encryption_private_key: %s
  listen_address: "%s"
  listen_port: 4789
  bind_interface: ""
  replay_window: 64
  max_clock_skew_seconds: 120
  session_timeout_seconds: 30
  peer_block_seconds: 5
  tun:
    enabled: true
    name: nls0
    mtu: 1280
  peers: []
""" % (router_id, state / "identity" / "ed25519.key", state / "identity" / "rsa-encryption.pem", state / "identity" / "rsa-signing.pem", listen_address),
        encoding="utf-8",
    )
    (config / "router.yaml").write_text(
        """router:
  interfaces:
    lan0:
      enabled: true
      nls_role: lan
      addresses: ["10.1.0.1/24"]
    wan0:
      enabled: true
      nls_role: wan
      addresses: ["192.0.2.1/24"]
""",
        encoding="utf-8",
    )
    entries = []
    for item in peers:
        entries.append(
            {
                "id": item["id"],
                "prefix": item["prefix"],
                "label": item["label"],
                "public_key": item["public_key"],
                "endpoint": item["endpoint"],
                "encryption_public_key": item["encryption_public_key"],
                "signing_public_key": item["signing_public_key"],
            }
        )
    import yaml
    (config / "router-ca.yaml").write_text(yaml.safe_dump({"entries": entries}), encoding="utf-8")
    (state / "identity" / "ed25519.key").write_bytes(b"")
    return config, state


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root/network namespaces")
def test_client_router_a_router_b_server_and_return_path():
    namespaces = ["nls-client", "nls-ra", "nls-rb", "nls-server"]
    procs = []
    with tempfile.TemporaryDirectory(prefix="nlsxnetos-integration-") as td:
        root = Path(td)
        try:
            for ns in namespaces:
                run("ip", "netns", "add", ns)

            make_veth("nls-client", "c0", "nls-ra", "lan0")
            make_veth("nls-ra", "wan0", "nls-rb", "wan0")
            make_veth("nls-rb", "lan0", "nls-server", "s0")

            addr("nls-client", "c0", "10.1.0.2/24")
            addr("nls-ra", "lan0", "10.1.0.1/24")
            addr("nls-ra", "wan0", "192.0.2.1/24")
            addr("nls-rb", "wan0", "192.0.2.2/24")
            addr("nls-rb", "lan0", "10.2.0.1/24")
            addr("nls-server", "s0", "10.2.0.2/24")

            for ns, iface in [("nls-client", "c0"), ("nls-ra", "lan0"), ("nls-ra", "wan0"),
                              ("nls-rb", "wan0"), ("nls-rb", "lan0"), ("nls-server", "s0")]:
                ns_exec(ns, "ip", "link", "set", iface, "up")

            route("nls-client", "add", "default", "via", "10.1.0.1", "dev", "c0")
            route("nls-server", "add", "default", "via", "10.2.0.1", "dev", "s0")
            # Enable forwarding only in the two routers.
            ns_exec("nls-ra", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            ns_exec("nls-rb", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")

            a = Ed25519PrivateKey.generate()
            b = Ed25519PrivateKey.generate()
            a_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            b_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            a_signing_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            b_signing_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            a_pub = base64.b64encode(a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            b_pub = base64.b64encode(b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

            ra_root = root / "ra"
            rb_root = root / "rb"
            write_config(ra_root, "router-a", "192.0.2.1", [{
                "id": 2, "prefix": "10.2.0.0/24", "label": "router-b",
                "public_key": b_pub, "endpoint": "192.0.2.2:4789", "encryption_public_key": rsa_public_key_b64(b_rsa), "signing_public_key": rsa_signing_public_key_b64(b_signing_rsa)
            }])
            write_config(rb_root, "router-b", "192.0.2.2", [{
                "id": 1, "prefix": "10.1.0.0/24", "label": "router-a",
                "public_key": a_pub, "endpoint": "192.0.2.1:4789", "encryption_public_key": rsa_public_key_b64(a_rsa), "signing_public_key": rsa_signing_public_key_b64(a_signing_rsa)
            }])
            (ra_root / "state/identity/ed25519.key").write_bytes(
                a.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            )
            (rb_root / "state/identity/ed25519.key").write_bytes(
                b.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            )
            (ra_root / "state/identity/rsa-encryption.pem").write_bytes(
                a_rsa.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            (rb_root / "state/identity/rsa-encryption.pem").write_bytes(
                b_rsa.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            (ra_root / "state/identity/rsa-signing.pem").write_bytes(
                a_signing_rsa.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            (rb_root / "state/identity/rsa-signing.pem").write_bytes(
                b_signing_rsa.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )

            env_a = os.environ.copy()
            env_a.update(
                NLSXNETOS_CONFIG_DIR=str(ra_root / "etc"),
                NLSXNETOS_ROUTER_CA_PATH=str(ra_root / "etc/router-ca.yaml"),
                NLSXNETOS_ROUTE_STATE=str(ra_root / "routes.json"),
            )
            env_b = os.environ.copy()
            env_b.update(
                NLSXNETOS_CONFIG_DIR=str(rb_root / "etc"),
                NLSXNETOS_ROUTER_CA_PATH=str(rb_root / "etc/router-ca.yaml"),
                NLSXNETOS_ROUTE_STATE=str(rb_root / "routes.json"),
            )
            # Identity paths are absolute in each generated configuration.
            for ns, env in [("nls-ra", env_a), ("nls-rb", env_b)]:
                rootdir = ra_root if ns == "nls-ra" else rb_root
                cmd = ["ip", "netns", "exec", ns, os.sys.executable, "-m", "nlsxnetos", "nls", "run"]
                procs.append(subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True))

            # Wait for the UDP listeners and TUN routes to appear.
            deadline = time.time() + 15
            while time.time() < deadline:
                ra_ok = ns_exec("nls-ra", "ip", "link", "show", "nls0", check=False).returncode == 0
                rb_ok = ns_exec("nls-rb", "ip", "link", "show", "nls0", check=False).returncode == 0
                if ra_ok and rb_ok:
                    break
                time.sleep(0.2)
            else:
                output = []
                for proc in procs:
                    if proc.poll() is not None:
                        output.append(proc.stdout.read() if proc.stdout else "")
                raise AssertionError("NLS TUN interfaces did not become ready\\n" + "\\n".join(output))

            if any(proc.poll() is not None for proc in procs):
                output = []
                for proc in procs:
                    if proc.poll() is not None and proc.stdout:
                        output.append(proc.stdout.read())
                raise AssertionError("NLS daemon exited before traffic test\\n" + "\\n".join(output))
            # Ordinary client traffic: no NLS command is issued in the client namespace.
            try:
                ns_exec("nls-client", "ping", "-c", "3", "-W", "2", "10.2.0.2")
                ns_exec("nls-server", "ping", "-c", "3", "-W", "2", "10.1.0.2")

                # Exercise inner MTUs below the configured NLS TUN MTU.
                for payload in ("1200", "1280", "1350"):
                    ns_exec("nls-client", "ping", "-c", "2", "-W", "3", "-s", payload, "10.2.0.2")
                # Force IPv4 fragmentation inside the NLS TUN.
                ns_exec("nls-client", "ping", "-c", "2", "-W", "4", "-s", "1380", "10.2.0.2")

                server = subprocess.Popen(
                    ["ip", "netns", "exec", "nls-server", "iperf3", "-s", "-1"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    time.sleep(0.5)
                    result = ns_exec(
                        "nls-client", "iperf3", "-c", "10.2.0.2", "-t", "5", "-J"
                    )
                    import json
                    report = json.loads(result.stdout)
                    bps = report["end"]["sum_received"]["bits_per_second"]
                    assert bps > 1_000_000, f"NLS throughput too low: {bps} bit/s"
                finally:
                    server.terminate()
            except Exception as exc:
                diagnostics = []
                for ns in ("nls-ra", "nls-rb"):
                    diagnostics.append(ns + " routes\n" + ns_exec(ns, "ip", "route", "show", check=False).stdout)
                    diagnostics.append(ns + " links\n" + ns_exec(ns, "ip", "-br", "link", check=False).stdout)
                    diagnostics.append(ns + " sockets\n" + ns_exec(ns, "ss", "-lunp", check=False).stdout)
                for proc in procs:
                    proc.send_signal(signal.SIGTERM)
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
                    if proc.stdout:
                        diagnostics.append(proc.stdout.read())
                raise AssertionError("NLS traffic path failed\n" + "\n".join(diagnostics)) from exc
        finally:
            for p in procs:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
            for ns in namespaces:
                run("ip", "netns", "del", ns, check=False)
