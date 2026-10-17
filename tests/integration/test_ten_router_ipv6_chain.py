import base64
import json
import cbor2
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from test_four_node_nls import _issue_router_certificate, _root_cert
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from nls.rsa import public_key_b64 as rsa_public_key_b64
from nls.ca_client import ClientSettings, _save_verified_cache


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
CLIENT_IP = "fd00:1234:5678:a1b2::100"
SERVER_IP = "fd00:300::10"
VIP_POOL_R1 = "fd42:1::/64"
VIP_POOL_R10 = "fd42:10::/64"


def run(*args, ns=None, check=True, timeout=15):
    cmd = ["ip", "netns", "exec", ns, *args] if ns else list(args)
    try:
        return subprocess.run(
            cmd, check=check, text=True, capture_output=True, timeout=timeout
        )
    except subprocess.CalledProcessError as exc:
        print("NLS_TEST_SUBPROCESS_FAILURE " + json.dumps({
            "namespace": ns,
            "argv": cmd,
            "returncode": exc.returncode,
            "stdout": exc.stdout,
            "stderr": exc.stderr,
        }, sort_keys=True), flush=True)
        raise


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
    ns_exec(ns, "ip", "-6", "addr", "add", address, "dev", interface, "nodad")


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


def write_config(root, router_id, endpoint, bind_interface, identity_path, entries,
                 ca_key=None, root_cert_pem=b"", local_cert_pem=b"", nls_routes=None):
    etc = root / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "router-ca").mkdir(parents=True, exist_ok=True)
    (root / "state" / "identity").mkdir(parents=True, exist_ok=True)
    (root / "state" / "rollback").mkdir(parents=True, exist_ok=True)
    config = {
        "nls": {
            "enabled": True, "protocol_version": 1, "router_id": router_id,
            "identity_key": str(identity_path),
            "encryption_private_key": str(identity_path.with_name("rsa-encryption.pem")),
            "listen_address": endpoint, "listen_port": 4789,
            "bind_interface": bind_interface, "replay_window": 64,
            "max_clock_skew_seconds": 120, "session_timeout_seconds": 60,
            "peer_block_seconds": 5, "tun": {"enabled": True, "name": "nls0", "mtu": 1280},
            "peers": [],
        }
    }
    (etc / "nls.yaml").write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    ca_key = ca_key or Ed25519PrivateKey.generate()
    ca_public = ca_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ca_private_path = etc / "ca-test-signing.key"
    ca_private_path.write_bytes(ca_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    root_path = etc / "router-ca" / "ca-root.crt"
    root_path.write_bytes(root_cert_pem)
    (root / "state" / "identity" / "router.crt").write_bytes(local_cert_pem)
    (etc / "router-ca-client.yaml").write_text(
        yaml.safe_dump({"router_ca": {
            "endpoint": "[fd00:100:5::2]:4790", "server_id": "nls-router-ca-test",
            "server_public_key": base64.b64encode(ca_public).decode(),
            "router_id": router_id, "identity_key": str(identity_path),
            "certificate_file": str(root / "state" / "identity" / "router.crt"),
            "ca_certificate_file": str(root_path), "nls_config_file": str(etc / "nls.yaml"),
            "directory_file": str(etc / "router-directory.json"),
            "rollback_mark_file": str(root / "state" / "rollback" / "directory-rollback-mark.json"),
            "encryption_private_key": str(identity_path.with_name("rsa-encryption.pem")),
        }}, sort_keys=False), encoding="utf-8",
    )
    (etc / "router.yaml").write_text(
        yaml.safe_dump({"router": {"interfaces": {}, "nls_routes": nls_routes or []}}, sort_keys=False),
        encoding="utf-8",
    )
    now = int(time.time())
    signed_records = []
    for item in entries:
        rsa_pub = serialization.load_der_public_key(base64.b64decode(item["encryption_public_key"]))
        rsa_pem = rsa_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        record = {
            "router_id": item.get("router_id", item["label"]),
            "ed25519_public_key": item["public_key"],
            "rsa_encryption_public_key": rsa_pem,
            "wan_endpoints": item.get("wan_endpoints", [item["endpoint"]]),
            "gateway_ips": [], "prefixes": [item["prefix"]],
            "certificate_serial": item.get("certificate_serial", "1000"),
            "status": "ACTIVE", "record_seq": 1, "issued_at": now, "valid_until": now + 600,
        }
        signed_records.append({
            "payload": record, "signer_public_key": base64.b64encode(ca_public).decode(),
            "signature": base64.b64encode(ca_key.sign(b"NLS-DIR-v1" + cbor2.dumps(record, canonical=True))).decode(),
            "encoding": "canonical-cbor", "domain": "NLS-DIR-v1",
        })
    payload = {
        "directory_seq": 1, "issued_at": now, "expires_at": now + 600,
        "records": signed_records, "revoked_serials": [],
        "policy": {
            "allowed_suites": ["X25519-HKDF-SHA256-AES-256-GCM-Ed25519-RSA-OAEP-SHA256"],
            "minimum_nls_version": 1, "replay_window": 64,
            "handshake_timeout_seconds": 5, "lookup_validity_seconds": 30,
        },
    }
    bundle = {
        "payload": payload, "signer_public_key": base64.b64encode(ca_public).decode(),
        "signature": base64.b64encode(ca_key.sign(b"NLS-DIR-v1" + cbor2.dumps(payload, canonical=True))).decode(),
        "encoding": "canonical-cbor", "domain": "NLS-DIR-v1",
    }
    # The handshake requires a fresh, signed lookup record (valid for <=30 seconds),
    # not only the longer-lived directory bundle record. Include a nonce in each signed
    # lookup fixture so this lab models the S3/S4 freshness contract.
    lookup_envelopes = {}
    for envelope in signed_records:
        lookup_record = dict(envelope["payload"])
        lookup_record["client_nonce"] = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        lookup_record["issued_at"] = now
        lookup_record["valid_until"] = min(int(lookup_record["valid_until"]), now + 30)
        lookup_envelopes[lookup_record["router_id"]] = {
            "payload": lookup_record,
            "signer_public_key": base64.b64encode(ca_public).decode(),
            "signature": base64.b64encode(ca_key.sign(
                b"NLS-DIR-v1" + cbor2.dumps(lookup_record, canonical=True)
            )).decode(),
            "encoding": "canonical-cbor",
            "domain": "NLS-DIR-v1",
        }
    settings = ClientSettings.load(etc / "router-ca-client.yaml")
    # A signed cache is not trusted without its independent, mode-0600 rollback mark.
    # Use the production writer so the fixture exercises the same invariant as live sync.
    _save_verified_cache(settings, bundle=bundle, lookups=lookup_envelopes, allow_mark_repair=True)

def _test_ca_runner_script():
    """Use signed local lookup fixtures; this topology does not start a Router-CA."""
    return r'''
import base64, copy, json, os, secrets, signal, time
from pathlib import Path
import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nls import ca_client

latest = {}

def fake_lookup(settings, identity_key, target_router_id):
    cache = json.loads(Path(settings.directory_file).read_text(encoding="utf-8"))
    bundle = ca_client._verify_directory_envelope(cache["bundle"], settings)
    source = None
    for envelope in bundle.get("records", []):
        record = ca_client._verify_directory_envelope(envelope, settings)
        if record.get("router_id") == target_router_id:
            source = record
            break
    if source is None:
        raise RuntimeError("ten-router signed fixture: unknown target")
    record = copy.deepcopy(source)
    now = int(time.time())
    record["issued_at"] = now
    record["valid_until"] = min(int(record.get("valid_until", now + 30)), now + 30)
    record["client_nonce"] = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode("ascii").rstrip("=")
    key = Ed25519PrivateKey.from_private_bytes(
        Path(os.environ["NLS_TEST_CA_SIGNING_KEY"]).read_bytes()
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    envelope = {
        "payload": record,
        "signer_public_key": base64.b64encode(public).decode("ascii"),
        "signature": base64.b64encode(
            key.sign(b"NLS-DIR-v1" + cbor2.dumps(record, canonical=True))
        ).decode("ascii"),
        "encoding": "canonical-cbor",
        "domain": "NLS-DIR-v1",
    }
    latest[target_router_id] = envelope
    return record

def fake_lookup_envelope(router_id, settings):
    if router_id not in latest:
        raise RuntimeError("ten-router signed fixture: lookup envelope missing")
    return latest[router_id]

ca_client.lookup = fake_lookup
ca_client.lookup_envelope = fake_lookup_envelope

import cProfile, logging
from nls.config import load
from nls.daemon import NLSDaemon
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
daemon = NLSDaemon(load())
_profile_path = os.environ.get("NLS_CPROFILE_OUT")
_profiler = None
def _start_profile(signum, frame):
    global _profiler
    if not _profile_path or _profiler is not None:
        return
    _profiler = cProfile.Profile()
    _profiler.enable()
def _stop_profile(signum, frame):
    global _profiler
    if _profiler is not None and _profile_path:
        _profiler.disable()
        _profiler.dump_stats(_profile_path)
        _profiler = None
signal.signal(signal.SIGTERM, daemon._shutdown)
signal.signal(signal.SIGINT, daemon._shutdown)
if hasattr(signal, "SIGRTMIN"):
    signal.signal(signal.SIGRTMIN, _start_profile)
    signal.signal(signal.SIGRTMIN + 1, _stop_profile)
try:
    daemon.run()
finally:
    if _profiler is not None and _profile_path:
        _profiler.disable()
        _profiler.dump_stats(_profile_path + ".final.prof")
'''


def daemon_env(root):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path.cwd())
    env["NLSXNETOS_CONFIG_DIR"] = str(root / "etc")
    env["NLSXNETOS_ROUTER_CA_PATH"] = str(root / "etc" / "router-ca.yaml")
    env["NLSXNETOS_ROUTER_CA_DIRECTORY"] = str(root / "etc" / "router-directory.json")
    env["NLSXNETOS_ROUTER_CA_CLIENT_CONFIG"] = str(root / "etc" / "router-ca-client.yaml")
    env["NLSXNETOS_ROUTE_STATE"] = str(root / "routes.json")
    # Each namespace is a separate router process but shares the host filesystem;
    # isolate runtime status files so concurrent routers cannot race on one .tmp file.
    env["NLSXNETOS_NLS_STATUS_PATH"] = str(root / "nls-status.json")
    env["NLSXNETOS_VIP_STATE"] = str(root / "vip-state.json")
    if root.name == "nls-r1":
        env["NLSXNETOS_VIP_POOL"] = VIP_POOL_R1
        env["NLS_TEST_CA_SIGNING_KEY"] = str(root / "etc" / "ca-test-signing.key")
    elif root.name == "nls-r10":
        env["NLSXNETOS_VIP_POOL"] = VIP_POOL_R10
        env["NLS_TEST_CA_SIGNING_KEY"] = str(root / "etc" / "ca-test-signing.key")
    return env


def start_daemon(ns, env):
    return subprocess.Popen(
        ["ip", "netns", "exec", ns, "python3", "-u", "-m", "tools.nlsxnetos", "nls", "run"],
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
        f"s.bind(({CLIENT_IP!r},0)); "
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
                f"{TEMP_ROUTER_CA_ADDRESS}/128", "dev", "lo", "nodad",
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

            # R10 -> R1. R10 itself uses R9 as its next hop.
            add_route(ROUTERS[-1], f"{R1_NLS_ENDPOINT}/128", via="fd00:100:9::1", dev="left")
            for i in range(9, 2, -1):
                current = ROUTERS[i - 1]
                next_hop = f"fd00:100:{i-1}::1"
                add_route(current, f"{R1_NLS_ENDPOINT}/128", via=next_hop, dev="left")

            # Directional routable vIP pools: R1 bootstrap addresses return left,
            # R10 bootstrap addresses return right, and each intermediate router
            # forwards each pool toward its owning edge router.
            for i in range(1, 10):
                current = ROUTERS[i - 1]
                next_hop = f"fd00:100:{i}::2"
                dev = "wan0" if i == 1 else "right"
                add_route(current, VIP_POOL_R10, via=next_hop, dev=dev)
            for i in range(2, 11):
                current = ROUTERS[i - 1]
                next_hop = f"fd00:100:{i-1}::1"
                add_route(current, VIP_POOL_R1, via=next_hop, dev="left")

            # Preflight: every configured NLS listen address must already
            # belong to its router namespace. If this fails, it is a topology
            # setup error rather than an NLS socket failure.
            expected_endpoints = [R1_NLS_ENDPOINT] + [
                f"fd00:100:{i}::1" for i in range(2, 10)
            ] + [R10_NLS_ENDPOINT]
            for ns, expected in zip(ROUTERS, expected_endpoints):
                addresses = ns_exec(ns, "ip", "-6", "addr", "show").stdout
                assert expected in addresses, (
                    f"{ns} is missing NLS endpoint {expected}\n{addresses}"
                )

            identities = {}
            for i, ns in enumerate(ROUTERS, 1):
                private, public = generate_identity()
                identities[i] = {"private": private, "public": public, "rsa": rsa.generate_private_key(public_exponent=65537, key_size=3072)}
                path = root / ns / "state" / "identity"
                path.mkdir(parents=True)
                (path / "ed25519.key").write_bytes(private)
                (path / "rsa-encryption.pem").write_bytes(
                    identities[i]["rsa"].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
                )

            ca_key = Ed25519PrivateKey.generate()
            root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            root_cert = _root_cert(root_key, name="NLS Ten-Router Test Root", serial=0x2000)
            root_pem = root_cert.public_bytes(Encoding.PEM)
            certs = {}
            for endpoint_id in (1, 10):
                identity_key = Ed25519PrivateKey.from_private_bytes(identities[endpoint_id]["private"])
                cert_pem, serial = _issue_router_certificate(
                    f"router-{endpoint_id}", identity_key, root_key, root_cert, 0x200 + endpoint_id
                )
                certs[endpoint_id] = {"pem": cert_pem, "serial": serial}
            for i, ns in enumerate(ROUTERS, 1):
                rroot = root / ns
                identity_path = rroot / "state" / "identity" / "ed25519.key"

                if i == 1:
                    endpoint = R1_NLS_ENDPOINT
                    bind = ""
                    entries = [
                        {
                            "id": 1,
                            "prefix": "fd00:1234:5678:a1b2::/64",
                            "label": "router-1",
                            "public_key": identities[1]["public"],
                            "endpoint": f"[{R1_NLS_ENDPOINT}]:4789",
                            "encryption_public_key": rsa_public_key_b64(identities[1]["rsa"]),
                            "certificate_serial": certs[1]["serial"],
                        },
                        {
                            "id": 10,
                            "router_id": "router-10",
                            "prefix": "fd00:300::/64",
                            "label": "router-10-server",
                            "public_key": identities[10]["public"],
                            "endpoint": f"[{R10_NLS_ENDPOINT}]:4789",
                            "encryption_public_key": rsa_public_key_b64(identities[10]["rsa"]),
                            "certificate_serial": certs[10]["serial"],
                        },
                    ]
                elif i == 10:
                    endpoint = R10_NLS_ENDPOINT
                    bind = ""
                    entries = [
                        {
                            "id": 1,
                            "router_id": "router-1",
                            "prefix": "fd00:1234:5678:a1b2::/64",
                            "label": "router-1-client",
                            "public_key": identities[1]["public"],
                            "endpoint": f"[{R1_NLS_ENDPOINT}]:4789",
                            "encryption_public_key": rsa_public_key_b64(identities[1]["rsa"]),
                            "certificate_serial": certs[1]["serial"],
                        },
                        {
                            "id": 10,
                            "prefix": "fd00:300::/64",
                            "label": "router-10",
                            "public_key": identities[10]["public"],
                            "endpoint": f"[{R10_NLS_ENDPOINT}]:4789",
                            "encryption_public_key": rsa_public_key_b64(identities[10]["rsa"]),
                            "certificate_serial": certs[10]["serial"],
                        },
                    ]
                else:
                    # Intermediate routers do not terminate this NLS session,
                    # but the daemon still requires a valid active Router-CA
                    # entry before it starts.
                    endpoint = f"fd00:100:{i}::1"
                    bind = ""
                    entries = [{
                        "id": 1000 + i,
                        "router_id": "router-1",
                        "prefix": f"fd00:9000:{i}::/64",
                        "label": f"test-peer-{i}",
                        "public_key": identities[1]["public"],
                        "endpoint": f"[{R1_NLS_ENDPOINT}]:4789",
                        "encryption_public_key": rsa_public_key_b64(identities[1]["rsa"]),
                        "certificate_serial": certs[1]["serial"],
                    }]

                if i == 1:
                    routes = [{"prefix": "fd00:300::/64", "router_id": "router-10"}]
                    local_cert = certs[1]["pem"]
                elif i == 10:
                    routes = [{"prefix": "fd00:1234:5678:a1b2::/64", "router_id": "router-1"}]
                    local_cert = certs[10]["pem"]
                else:
                    routes = []
                    local_cert = b""
                write_config(
                    rroot, f"router-{i}", endpoint, bind, identity_path, entries,
                    ca_key=ca_key, root_cert_pem=root_pem, local_cert_pem=local_cert,
                    nls_routes=routes,
                )

            runner = root / "nls_v2_test_runner.py"
            runner.write_text(_test_ca_runner_script(), encoding="utf-8")
            for i, ns in enumerate(ROUTERS, 1):
                env = daemon_env(root / ns)
                if i in (1, 10):
                    processes.append(subprocess.Popen(
                        ["ip", "netns", "exec", ns, os.sys.executable, str(runner)],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    ))
                else:
                    processes.append(start_daemon(ns, env))

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
                    assert "dev right" in route, (i, route)

            # Actual application traffic: client and server have no NLS config.
            server = udp_echo_server("nls-server")
            try:
                try:
                    response = udp_client("nls-client", b"10-ROUTER-NLS-TEST")
                    assert response == "ACK:10-ROUTER-NLS-TEST"
                except Exception as exc:
                    diagnostics = []
                    for proc in processes:
                        proc.send_signal(signal.SIGTERM)
                    for i, proc in enumerate(processes, 1):
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=3)
                        if proc.stdout:
                            output = proc.stdout.read()
                            if output:
                                diagnostics.append(f"--- router-{i} ---\\n{output}")
                    raise AssertionError(
                        "10-router NLS application traffic failed\\n"
                        + "\\n".join(diagnostics)
                    ) from exc
            finally:
                server.terminate()
                try:
                    server.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    server.kill()

            # Reverse path is exercised by the UDP response.
            # Stop the daemons so their buffered stdout can be inspected.
            for proc in processes:
                proc.send_signal(signal.SIGTERM)
            endpoint_logs = ""
            intermediate_logs = ""
            for i, proc in enumerate(processes, 1):
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=4)
                if proc.stdout:
                    text = proc.stdout.read()
                    if i in (1, 10):
                        endpoint_logs += text
                    else:
                        intermediate_logs += text

            assert '"event":"nls_handshake_established"' in endpoint_logs
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
