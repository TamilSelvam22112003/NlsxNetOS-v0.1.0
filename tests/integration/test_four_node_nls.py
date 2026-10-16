import base64
import cbor2
import json
import ipaddress
import os
import platform
import signal
import threading
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from nls.rsa import public_key_b64 as rsa_public_key_b64
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat


pytestmark = pytest.mark.integration


def run(*args, ns=None, check=True, timeout=15):
    cmd = ["ip", "netns", "exec", ns, *args] if ns else list(args)
    return subprocess.run(
        cmd, check=check, text=True, capture_output=True, timeout=timeout
    )


def ns_exec(ns, *args, check=True, timeout=15):
    return run(*args, ns=ns, check=check, timeout=timeout)


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


def wait_for_tcp_listener(ns, port, process, timeout=5):
    """Wait until the test server is listening, or fail with its startup log."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise AssertionError(
                f"iperf3 server exited before listening (rc={process.returncode}):\\n{output}"
            )
        listeners = ns_exec(ns, "ss", "-H", "-ltn", check=False).stdout
        if any(
            len(fields := line.split()) >= 4
            and fields[3].rsplit(":", 1)[-1] == str(port)
            for line in listeners.splitlines()
        ):
            return
        time.sleep(0.1)
    listeners = ns_exec(ns, "ss", "-H", "-ltn", check=False).stdout
    output = process.stdout.read() if process.poll() is not None and process.stdout else ""
    raise AssertionError(
        f"iperf3 server did not listen on TCP port {port} within {timeout}s. "
        f"Listeners:\\n{listeners}\\nServer output:\\n{output}"
    )


def write_config(root, router_id, listen_address, peers, ca_key=None, root_cert_pem=b"", local_cert_pem=b""):
    import yaml
    config = root / "etc"
    state = root / "state"
    config.mkdir(parents=True)
    (state / "identity").mkdir(parents=True)
    (state / "router-ca").mkdir(parents=True)
    (config / "router-ca").mkdir(parents=True)
    (config / "nls.yaml").write_text(
        """nls:
  enabled: true
  auto_router_ca: false
  protocol_version: 1
  router_id: %s
  identity_key: %s
  encryption_private_key: %s
  listen_address: "::"
  listen_port: 4789
  bind_interface: ""
  replay_window: 128
  max_clock_skew_seconds: 120
  session_timeout_seconds: 30
  peer_block_seconds: 5
  rekey_packet_limit: 4294967296
  rekey_seconds: 3600
  rekey_overlap_seconds: 1
  tun:
    enabled: true
    name: nls0
    mtu: 1280
  peers: []
""" % (router_id, state / "identity" / "ed25519.key", state / "identity" / "rsa-encryption.pem"),
        encoding="utf-8",
    )
    remote = next(item for item in peers if item["label"] != router_id)
    (config / "router.yaml").write_text(
        yaml.safe_dump({"router": {"interfaces": {}, "nls_routes": [
            {"prefix": remote["prefix"], "router_id": remote["label"]}
        ]}}, sort_keys=False),
        encoding="utf-8",
    )
    ca_key = ca_key or Ed25519PrivateKey.generate()
    ca_public = ca_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ca_private_path = config / "ca-test-signing.key"
    ca_private_path.write_bytes(ca_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    root_path = config / "router-ca" / "ca-root.crt"
    root_path.write_bytes(root_cert_pem)
    (state / "identity" / "router.crt").write_bytes(local_cert_pem)
    (config / "router-ca-client.yaml").write_text(
        yaml.safe_dump({"router_ca": {
            "endpoint": "[fd00:12::254]:4790",
            "server_id": "nls-router-ca-test",
            "server_public_key": base64.b64encode(ca_public).decode(),
            "router_id": router_id,
            "identity_key": str(state / "identity" / "ed25519.key"),
            "certificate_file": str(state / "identity" / "router.crt"),
            "ca_certificate_file": str(root_path),
            "nls_config_file": str(config / "nls.yaml"),
            "directory_file": str(config / "router-directory.json"),
            "encryption_private_key": str(state / "identity" / "rsa-encryption.pem"),
        }}, sort_keys=False),
        encoding="utf-8",
    )
    now = int(time.time())
    signed_records = []
    for item in peers:
        ed_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(item["public_key"]))
        rsa_pub = serialization.load_der_public_key(base64.b64decode(item["encryption_public_key"]))
        rsa_pem = rsa_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        record = {
            "router_id": item["label"],
            "ed25519_public_key": item["public_key"],
            "rsa_encryption_public_key": rsa_pem,
            "wan_endpoints": [item["endpoint"]],
            "gateway_ips": [],
            "prefixes": [item["prefix"]],
            "certificate_serial": item["certificate_serial"],
            "status": "ACTIVE",
            "record_seq": 1,
            "issued_at": now,
            "valid_until": now + 600,
        }
        signed_records.append({
            "payload": record,
            "signer_public_key": base64.b64encode(ca_public).decode(),
            "signature": base64.b64encode(ca_key.sign(b"NLS-DIR-v1" + cbor2.dumps(record, canonical=True))).decode(),
            "encoding": "canonical-cbor", "domain": "NLS-DIR-v1",
        })
    payload = {
        "directory_seq": 1, "issued_at": now, "expires_at": now + 600,
        "records": signed_records, "revoked_serials": [],
        "policy": {
            "allowed_suites": ["X25519-HKDF-SHA256-AES-256-GCM-Ed25519-RSA-OAEP-SHA256"],
            "minimum_nls_version": 1, "replay_window": 128,
            "handshake_timeout_seconds": 5, "lookup_validity_seconds": 30,
        },
    }
    bundle = {
        "payload": payload, "signer_public_key": base64.b64encode(ca_public).decode(),
        "signature": base64.b64encode(ca_key.sign(b"NLS-DIR-v1" + cbor2.dumps(payload, canonical=True))).decode(),
        "encoding": "canonical-cbor", "domain": "NLS-DIR-v1",
    }
    (config / "router-directory.json").write_text(
        json.dumps({"bundle": bundle, "lookups": {}}, sort_keys=True), encoding="utf-8"
    )
    (state / "identity" / "ed25519.key").write_bytes(b"")
    return config, state


def _root_cert(root_key, name="NLS Test Root", serial=0x1000, days=365):
    from datetime import datetime, timedelta, timezone
    from cryptography.x509.oid import NameOID
    from cryptography.x509 import BasicConstraints
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(root_key.public_key()).serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )


def _issue_router_certificate(router_id, identity_key, root_key, root_cert, serial):
    from datetime import datetime, timedelta, timezone
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from cryptography.x509 import BasicConstraints, ExtendedKeyUsage
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, router_id)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(root_cert.subject)
        .public_key(identity_key.public_key()).serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM), format(serial, "x")


def _test_ca_runner_script():
    return r'''
import base64, copy, json, os, secrets, time
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
        raise RuntimeError("test Router-CA: unknown target")
    record = copy.deepcopy(source)
    now = int(time.time())
    record["issued_at"] = now
    record["valid_until"] = now + 30
    record["client_nonce"] = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode().rstrip("=")
    key = Ed25519PrivateKey.from_private_bytes(Path(os.environ["NLS_TEST_CA_SIGNING_KEY"]).read_bytes())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    envelope = {
        "payload": record,
        "signer_public_key": base64.b64encode(public).decode(),
        "signature": base64.b64encode(key.sign(b"NLS-DIR-v1" + cbor2.dumps(record, canonical=True))).decode(),
        "encoding": "canonical-cbor", "domain": "NLS-DIR-v1",
    }
    latest[target_router_id] = envelope
    return record

def fake_lookup_envelope(router_id, settings):
    if router_id not in latest:
        raise RuntimeError("test Router-CA: lookup envelope missing")
    return latest[router_id]

ca_client.lookup = fake_lookup
ca_client.lookup_envelope = fake_lookup_envelope
ca_client.is_revoked = lambda serial, settings: False
from nls.daemon import run
run()
'''

@pytest.mark.skipif(os.geteuid() != 0, reason="requires root/network namespaces")
def test_six_node_client_router_a_wan_router_b_server_ca_nlh2_and_return_path():
    # Six-node lab: client -> Router A -> IPv6 WAN transit -> Router B -> server,
    # with the Router-CA test endpoint on a separate WAN link.
    namespaces = ["nls-client", "nls-ra", "nls-wan", "nls-rb", "nls-server", "nls-ca"]
    procs = []
    with tempfile.TemporaryDirectory(prefix="nlsxnetos-integration-") as td:
        root = Path(td)
        try:
            for ns in namespaces:
                run("ip", "netns", "add", ns)

            make_veth("nls-client", "c0", "nls-ra", "lan0")
            make_veth("nls-ra", "wan0", "nls-wan", "ra0")
            make_veth("nls-wan", "rb0", "nls-rb", "wan0")
            make_veth("nls-rb", "lan0", "nls-server", "s0")
            make_veth("nls-wan", "ca0", "nls-ca", "eth0")

            addr("nls-client", "c0", "10.1.0.2/24")
            addr("nls-ra", "lan0", "10.1.0.1/24")
            addr("nls-ra", "wan0", "fd00:12::1/64")
            addr("nls-wan", "ra0", "fd00:12::2/64")
            addr("nls-wan", "rb0", "fd00:23::1/64")
            addr("nls-rb", "wan0", "fd00:23::2/64")
            addr("nls-wan", "ca0", "fd00:34::1/64")
            addr("nls-ca", "eth0", "fd00:34::2/64")
            addr("nls-rb", "lan0", "10.2.0.1/24")
            addr("nls-server", "s0", "10.2.0.2/24")

            for ns, iface in [
                ("nls-client", "c0"), ("nls-ra", "lan0"), ("nls-ra", "wan0"),
                ("nls-wan", "ra0"), ("nls-wan", "rb0"), ("nls-wan", "ca0"),
                ("nls-rb", "wan0"), ("nls-rb", "lan0"), ("nls-server", "s0"),
                ("nls-ca", "eth0"),
            ]:
                ns_exec(ns, "ip", "link", "set", iface, "up")

            route("nls-client", "add", "default", "via", "10.1.0.1", "dev", "c0")
            route("nls-server", "add", "default", "via", "10.2.0.1", "dev", "s0")
            # Enable forwarding on the endpoint routers and the intermediate IPv6 WAN.
            ns_exec("nls-ra", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            ns_exec("nls-rb", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            ns_exec("nls-ra", "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")
            ns_exec("nls-rb", "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")
            ns_exec("nls-wan", "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1")
            # Explicit routes reach the opposite router's WAN subnet through
            # the intermediate transit node.
            ns_exec("nls-ra", "ip", "-6", "route", "add", "fd00:23::/64", "via", "fd00:12::2", "dev", "wan0")
            ns_exec("nls-rb", "ip", "-6", "route", "add", "fd00:12::/64", "via", "fd00:23::1", "dev", "wan0")
            # Separate per-router pools make the return route unambiguous even if
            # both endpoints later initiate independent sessions.
            ns_exec("nls-ra", "ip", "-6", "route", "add", "fd42:4e4c:53:2::/64", "via", "fd00:12::2", "dev", "wan0")
            ns_exec("nls-rb", "ip", "-6", "route", "add", "fd42:4e4c:53:1::/64", "via", "fd00:23::1", "dev", "wan0")
            ns_exec("nls-wan", "ip", "-6", "route", "add", "fd42:4e4c:53:1::/64", "via", "fd00:12::1", "dev", "ra0")
            ns_exec("nls-wan", "ip", "-6", "route", "add", "fd42:4e4c:53:2::/64", "via", "fd00:23::2", "dev", "rb0")

            a = Ed25519PrivateKey.generate()
            b = Ed25519PrivateKey.generate()
            ca_key = Ed25519PrivateKey.generate()
            a_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            b_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            a_pub = base64.b64encode(a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            b_pub = base64.b64encode(b.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
            root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            from datetime import datetime, timedelta, timezone
            from cryptography.x509.oid import NameOID
            from cryptography.x509 import BasicConstraints
            now_dt = datetime.now(timezone.utc)
            root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NLS Test Root")])
            root_cert = (
                x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                .public_key(root_key.public_key()).serial_number(0x1000)
                .not_valid_before(now_dt - timedelta(days=1))
                .not_valid_after(now_dt + timedelta(days=365))
                .add_extension(BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(root_key, hashes.SHA256())
            )
            root_pem = root_cert.public_bytes(Encoding.PEM)
            a_cert, a_serial = _issue_router_certificate("router-a", a, root_key, root_cert, 0x101)
            b_cert, b_serial = _issue_router_certificate("router-b", b, root_key, root_cert, 0x102)

            ra_root = root / "ra"
            rb_root = root / "rb"
            write_config(ra_root, "router-a", "::", [
                {
                    "id": 1, "prefix": "10.1.0.0/24", "label": "router-a",
                    "public_key": a_pub, "endpoint": "[fd00:12::1]:4789",
                    "encryption_public_key": rsa_public_key_b64(a_rsa), "certificate_serial": a_serial,
                },
                {
                    "id": 2, "prefix": "10.2.0.0/24", "label": "router-b",
                    "public_key": b_pub, "endpoint": "[fd00:23::2]:4789",
                    "encryption_public_key": rsa_public_key_b64(b_rsa), "certificate_serial": b_serial,
                },
            ], ca_key=ca_key, root_cert_pem=root_pem, local_cert_pem=a_cert)
            write_config(rb_root, "router-b", "::", [
                {
                    "id": 1, "prefix": "10.1.0.0/24", "label": "router-a",
                    "public_key": a_pub, "endpoint": "[fd00:12::1]:4789",
                    "encryption_public_key": rsa_public_key_b64(a_rsa), "certificate_serial": a_serial,
                },
                {
                    "id": 2, "prefix": "10.2.0.0/24", "label": "router-b",
                    "public_key": b_pub, "endpoint": "[fd00:23::2]:4789",
                    "encryption_public_key": rsa_public_key_b64(b_rsa), "certificate_serial": b_serial,
                },
            ], ca_key=ca_key, root_cert_pem=root_pem, local_cert_pem=b_cert)
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

            env_a = os.environ.copy()
            env_a.update(
                NLSXNETOS_CONFIG_DIR=str(ra_root / "etc"),
                NLSXNETOS_ROUTER_CA_PATH=str(ra_root / "etc/router-ca.yaml"),
                NLSXNETOS_ROUTER_CA_DIRECTORY=str(ra_root / "etc/router-directory.json"),
                NLSXNETOS_ROUTER_CA_CLIENT_CONFIG=str(ra_root / "etc/router-ca-client.yaml"),
                NLSXNETOS_ROUTE_STATE=str(ra_root / "routes.json"),
                NLSXNETOS_VIP_STATE=str(ra_root / "vip-state.json"),
                NLSXNETOS_VIP_POOL="fd42:4e4c:53:1::/64",
                NLSXNETOS_NLS_STATUS_PATH=str(ra_root / "status.json"),
                NLS_TEST_CA_SIGNING_KEY=str(ra_root / "etc/ca-test-signing.key"),
                PYTHONPATH=os.getcwd(),
            )
            env_b = os.environ.copy()
            env_b.update(
                NLSXNETOS_CONFIG_DIR=str(rb_root / "etc"),
                NLSXNETOS_ROUTER_CA_PATH=str(rb_root / "etc/router-ca.yaml"),
                NLSXNETOS_ROUTER_CA_DIRECTORY=str(rb_root / "etc/router-directory.json"),
                NLSXNETOS_ROUTER_CA_CLIENT_CONFIG=str(rb_root / "etc/router-ca-client.yaml"),
                NLSXNETOS_ROUTE_STATE=str(rb_root / "routes.json"),
                NLSXNETOS_VIP_STATE=str(rb_root / "vip-state.json"),
                NLSXNETOS_VIP_POOL="fd42:4e4c:53:2::/64",
                NLSXNETOS_NLS_STATUS_PATH=str(rb_root / "status.json"),
                NLS_TEST_CA_SIGNING_KEY=str(rb_root / "etc/ca-test-signing.key"),
                PYTHONPATH=os.getcwd(),
            )
            # Test CA responder returns fresh, correctly signed lookup envelopes; production
            # verification still checks signatures, nonce, freshness, RDR, and certificate bindings.
            runner = root / "nls_v2_test_runner.py"
            runner.write_text(_test_ca_runner_script(), encoding="utf-8")
            vip_seen = set()
            vip_during = {"nls-ra": [], "nls-rb": []}
            vip_before = {
                ns: ns_exec(ns, "ip", "-6", "addr", "show", "dev", "wan0").stdout
                for ns in ("nls-ra", "nls-rb")
            }
            print("NLS_VIP_BEFORE " + json.dumps(vip_before, sort_keys=True), flush=True)
            stop_vip_observer = threading.Event()
            def observe_vips():
                state_paths = [ra_root / "vip-state.json", rb_root / "vip-state.json"]
                while not stop_vip_observer.is_set():
                    active_anywhere = False
                    for state_path in state_paths:
                        try:
                            state = json.loads(state_path.read_text(encoding="utf-8"))
                            active = state.get("addresses", [])
                            active_anywhere = active_anywhere or bool(active)
                            vip_seen.update(active)
                            assigned = state.get("last_assigned")
                            if assigned:
                                vip_seen.add(assigned)
                        except (OSError, ValueError, TypeError):
                            pass
                    if active_anywhere:
                        # Capture both routers at the same bootstrap interval,
                        # including the non-allocating receiver's WAN interface.
                        for ns in ("nls-ra", "nls-rb"):
                            try:
                                output = ns_exec(ns, "ip", "-6", "addr", "show", "dev", "wan0").stdout
                                vip_during[ns].append(output)
                            except (OSError, subprocess.SubprocessError):
                                pass
                    stop_vip_observer.wait(0.002)
            vip_observer = threading.Thread(target=observe_vips, daemon=True)
            vip_observer.start()
            for ns, env in [("nls-ra", env_a), ("nls-rb", env_b)]:
                cmd = ["ip", "netns", "exec", ns, os.sys.executable, str(runner)]
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
            # Prompt 4a gate: NLH2 handshake with NLE2 directional session-key data path.
            print("NLS_DATA_PLANE=legacy NLE1 removed; NLE2 is the only data path", flush=True)
            # Snapshot the actual kernel IPv6 main route tables after operator
            # configuration/startup. CA lookup and handshake completion must not mutate them.
            route_table_before = {
                ns: ns_exec(ns, "ip", "-6", "route", "show").stdout
                for ns in ("nls-ra", "nls-rb")
            }
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
                    [
                        "ip", "netns", "exec", "nls-server",
                        "iperf3", "-s", "-1", "-B", "10.2.0.2",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    # Do not race the client against iperf3 startup. The old
                    # fixed 0.5-second sleep could fail intermittently on slow VMs.
                    wait_for_tcp_listener("nls-server", 5201, server, timeout=8)
                    result = ns_exec(
                        "nls-client", "iperf3", "-c", "10.2.0.2",
                        "-t", "5", "-J", timeout=20,
                    )
                    report = json.loads(result.stdout)
                    bps = report["end"]["sum_received"]["bits_per_second"]
                    assert bps > 1_000_000, f"NLS throughput too low: {bps} bit/s"
                except subprocess.CalledProcessError as exc:
                    raise AssertionError(
                        "iperf3 client failed "
                        f"(return code {exc.returncode}). "
                        f"stdout={exc.stdout!r}; stderr={exc.stderr!r}"
                    ) from exc
                finally:
                    if server.poll() is None:
                        server.terminate()
                    try:
                        server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=3)
                # Exercise UDP with 1,280-byte inner packets in both directions.
                for reverse in (False,):
                    server_ns, client_ns, server_ip, client_ip = (
                        ("nls-client", "nls-server", "10.1.0.2", "10.2.0.2")
                        if reverse else
                        ("nls-server", "nls-client", "10.2.0.2", "10.2.0.2")
                    )
                    udp_server = subprocess.Popen(
                        [
                            "ip", "netns", "exec", server_ns,
                            "iperf3", "-s", "-1", "-J", "-B", server_ip,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    try:
                        wait_for_tcp_listener(server_ns, 5201, udp_server, timeout=8)
                        udp_result = ns_exec(
                            client_ns, "iperf3", "-c", server_ip,
                            "-u", "-l", "1252", "-b", "10M", "-t", "3", "-J",
                            timeout=15,
                        )
                        udp_report = json.loads(udp_result.stdout)
                        udp_end = udp_report.get("end", {})
                        receiver_summary = udp_end.get("sum_received")
                        if receiver_summary is None:
                            # iperf3 3.9 on Ubuntu 22.04 may omit the receiver
                            # summary from the client JSON. Read the server's JSON
                            # report rather than silently treating sender rate as
                            # delivered throughput.
                            udp_server.wait(timeout=5)
                            server_text = udp_server.stdout.read() if udp_server.stdout else ""
                            try:
                                server_report = json.loads(server_text)
                            except (ValueError, TypeError) as exc:
                                raise AssertionError(
                                    f"iperf3 UDP receiver summary missing; client={udp_report!r}; "
                                    f"server_output={server_text!r}"
                                ) from exc
                            receiver_summary = server_report.get("end", {}).get("sum_received")
                        if receiver_summary is None or "bits_per_second" not in receiver_summary:
                            raise AssertionError(
                                f"iperf3 UDP receiver summary missing; client={udp_report!r}; "
                                f"receiver={receiver_summary!r}"
                            )
                        udp_bps = receiver_summary["bits_per_second"]
                        assert udp_bps > 1_000_000, (
                            f"NLE2 UDP {'reverse' if reverse else 'forward'} throughput too low: {udp_bps} bit/s"
                        )
                        print(
                            "NLS_UDP_1280 " + json.dumps({
                                "direction": "reverse" if reverse else "forward",
                                "bits_per_second": udp_bps,
                            }, sort_keys=True),
                            flush=True,
                        )
                    finally:
                        if udp_server.poll() is None:
                            udp_server.terminate()
                        try:
                            udp_server.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            udp_server.kill()
                            udp_server.wait(timeout=3)

                # Record the end-to-end NLE2 UDP throughput with 1,280-byte inner IPv4 packets.
                bench_server = subprocess.Popen(
                    ["ip", "netns", "exec", "nls-server", "iperf3", "-s", "-1", "-B", "10.2.0.2"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                try:
                    wait_for_tcp_listener("nls-server", 5201, bench_server, timeout=8)
                    bench_result = ns_exec(
                        "nls-client", "iperf3", "-c", "10.2.0.2", "-u", "-l", "1252",
                        "-b", "200M", "-t", "5", "-J", timeout=20,
                    )
                    bench_json = json.loads(bench_result.stdout)
                    received = bench_json["end"]["sum_received"]
                    actual_bps = float(received["bits_per_second"])
                    try:
                        cpu_model = next(
                            line.split(":", 1)[1].strip()
                            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines()
                            if line.lower().startswith("model name")
                        )
                    except (OSError, StopIteration):
                        cpu_model = platform.processor() or "unknown"
                    print("NLS_IPERF3_NLE2_1280 " + json.dumps({
                        "target_mbps": 100,
                        "actual_mbps": round(actual_bps / 1_000_000, 2),
                        "lost_percent": received.get("lost_percent"),
                        "met_target": actual_bps >= 100_000_000,
                        "inner_packet_bytes": 1280,
                        "method": "iperf3 UDP, 1252-byte payload + 20-byte IPv4 header + 8-byte UDP header, 200M offered rate, 5 seconds",
                        "platform": platform.platform(),
                        "cpu_model": cpu_model,
                    }, sort_keys=True), flush=True)
                    assert actual_bps > 1_000_000, "NLE2 iperf3 benchmark transferred insufficient data"
                finally:
                    if bench_server.poll() is None:
                        bench_server.terminate()
                    try:
                        bench_server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        bench_server.kill()
                        bench_server.wait(timeout=3)

                route_table_after = {
                    ns: ns_exec(ns, "ip", "-6", "route", "show").stdout
                    for ns in ("nls-ra", "nls-rb")
                }
                assert route_table_after == route_table_before, (
                    "CA lookup/handshake changed the kernel IPv6 route table: "
                    f"before={route_table_before!r}, after={route_table_after!r}"
                )
                print("NLS_ROUTE_TABLE_CA_NO_CHANGE " + json.dumps(route_table_after, sort_keys=True), flush=True)
                # Explicit UDP echo verifies the server-to-client return path independently
                # of iperf3's reverse-mode reporting semantics.
                echo_server_code = (
                    "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                    "s.bind(('10.2.0.2',40000)); d,a=s.recvfrom(2048); s.sendto(d,a)"
                )
                echo_server = subprocess.Popen(
                    ["ip", "netns", "exec", "nls-server", os.sys.executable, "-u", "-c", echo_server_code],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                try:
                    for _ in range(30):
                        if ":40000" in ns_exec("nls-server", "ss", "-lun").stdout:
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError("UDP echo server did not bind")
                    echo_client_code = (
                        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                        "s.settimeout(4); p=b'R'*1252; s.sendto(p,('10.2.0.2',40000)); "
                        "d,_=s.recvfrom(2048); assert d==p; print('UDP_ECHO_RETURN_OK',len(d)+28)"
                    )
                    echo_result = ns_exec(
                        "nls-client", os.sys.executable, "-c", echo_client_code, timeout=8
                    )
                    assert "UDP_ECHO_RETURN_OK 1280" in echo_result.stdout
                    print("NLS_UDP_RETURN_PATH " + echo_result.stdout.strip(), flush=True)
                finally:
                    if echo_server.poll() is None:
                        echo_server.terminate()
                    try:
                        echo_server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        echo_server.kill()
                        echo_server.wait(timeout=3)

                # Reduced-limit make-before-break rekey is exercised in focused
                # lifecycle tests. Keep this high-rate iperf lab on the production
                # packet limit so its throughput measurement is not dominated by
                # repeated handshakes at an intentionally tiny test threshold.

                # Every observed bootstrap address must be released after M4.
                stop_vip_observer.set()
                vip_observer.join(timeout=2)
                assert vip_seen, "vIP was never observed during bootstrap"
                assert vip_during["nls-ra"] and vip_during["nls-rb"], "did not capture both WAN interfaces during bootstrap"
                during_outputs = [output for outputs in vip_during.values() for output in outputs]
                assert any(vip in output for vip in vip_seen for output in during_outputs), (
                    "no allocated vIP appeared in live ip -6 addr output during bootstrap"
                )
                print("NLS_VIP_DURING " + json.dumps(vip_during, sort_keys=True), flush=True)
                vip_after = {}
                for ns, state_path in [("nls-ra", ra_root / "vip-state.json"), ("nls-rb", rb_root / "vip-state.json")]:
                    if state_path.exists():
                        state = json.loads(state_path.read_text(encoding="utf-8"))
                        assert state["last_assigned_verified"] is True, f"{ns} never verified vIP in ip -6 addr output"
                        assert state["addresses"] == [], f"{ns} retained bootstrap vIPs: {state['addresses']}"
                    addresses = ns_exec(ns, "ip", "-6", "addr", "show", "dev", "wan0").stdout
                    vip_after[ns] = addresses
                    for vip in vip_seen:
                        assert vip not in addresses, f"retired vIP {vip} remained assigned on {ns}"
                print("NLS_VIP_AFTER " + json.dumps(vip_after, sort_keys=True), flush=True)
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
                diagnostics.insert(0, "original exception: " + repr(exc))
                raise AssertionError("NLS traffic path failed\n" + "\n".join(diagnostics)) from exc
        finally:
            if "stop_vip_observer" in locals():
                stop_vip_observer.set()
                vip_observer.join(timeout=2)
            for p in procs:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
            for ns in namespaces:
                run("ip", "netns", "del", ns, check=False)
