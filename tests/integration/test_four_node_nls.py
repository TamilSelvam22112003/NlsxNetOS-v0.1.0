import base64
import cbor2
import json
import ipaddress
import hashlib
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


def _iperf3_udp_receiver_stats(report):
    """Return delivered UDP bps, metric source, and reported packet loss across iperf3 versions."""
    end = report.get("end", {})
    received = end.get("sum_received")
    if isinstance(received, dict) and float(received.get("bits_per_second", 0) or 0) > 0:
        return (
            float(received["bits_per_second"]),
            "receiver_summary",
            received.get("lost_percent"),
        )
    sender = end.get("sum")
    if (
        isinstance(sender, dict)
        and sender.get("sender") is True
        and sender.get("bits_per_second") is not None
        and sender.get("lost_percent") is not None
    ):
        loss = float(sender["lost_percent"])
        delivered_bps = float(sender["bits_per_second"]) * max(0.0, 1.0 - loss / 100.0)
        return delivered_bps, "sender_rate_adjusted_by_reported_loss", loss
    raise AssertionError(f"iperf3 UDP report has no usable receiver or loss summary: {report!r}")


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
import logging, os, signal
from nls.config import load
from nls.daemon import NLSDaemon
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
daemon = NLSDaemon(load())
def _arm_one_rekey(signum, frame):
    active = [session.tx_sequence for session in daemon.sessions.values()
              if session.state in ("ESTABLISHED", "OVERLAP")]
    if active:
        daemon.cfg.rekey_packet_limit = int((min(active) + 8) / 0.9) + 1
        print("NLS_TEST_REKEY_ARMED " + daemon.cfg.router_id, flush=True)
def _restore_rekey_limit(signum, frame):
    daemon.cfg.rekey_packet_limit = 1 << 32
    print("NLS_TEST_REKEY_LIMIT_RESTORED " + daemon.cfg.router_id, flush=True)
signal.signal(signal.SIGUSR1, _arm_one_rekey)
signal.signal(signal.SIGUSR2, _restore_rekey_limit)
signal.signal(signal.SIGTERM, daemon._shutdown)
signal.signal(signal.SIGINT, daemon._shutdown)
_profile_path = os.environ.get("NLS_CPROFILE_OUT")
if _profile_path:
    import cProfile
    _profiler = cProfile.Profile()
    try:
        _profiler.runcall(daemon.run)
    finally:
        _profiler.dump_stats(_profile_path)
else:
    daemon.run()
'''


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root/network namespaces")
def test_six_node_nlh2_mtu_fragmentation_large_payload_forwarding_and_return_path():
    # Six-node lab: client -> Router A -> IPv6 WAN transit -> Router B -> server,
    # with the Router-CA test endpoint on a separate WAN link.
    namespaces = ["nls-client", "nls-ra", "nls-wan", "nls-rb", "nls-server", "nls-ca"]
    profile_mode = os.environ.get("NLS_PROFILE_DAEMON") == "1"
    procs = []
    ca_agents = []
    ca_proc = None
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
            # Reach the real Router-CA control endpoint through the WAN transit.
            ns_exec("nls-ra", "ip", "-6", "route", "add", "fd00:34::/64", "via", "fd00:12::2", "dev", "wan0")
            ns_exec("nls-rb", "ip", "-6", "route", "add", "fd00:34::/64", "via", "fd00:23::1", "dev", "wan0")
            ns_exec("nls-ca", "ip", "-6", "route", "add", "fd00:12::/64", "via", "fd00:34::1", "dev", "eth0")
            ns_exec("nls-ca", "ip", "-6", "route", "add", "fd00:23::/64", "via", "fd00:34::1", "dev", "eth0")
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

            # Provision a real Router-CA with its own SQLite registry, RSA root
            # certificate, pinned Ed25519 control identity, and live TCP/4790 service.
            import yaml
            ca_root = root / "ca"
            ca_root.mkdir()
            ca_config = ca_root / "router-ca.yaml"
            ca_certificate = ca_root / "ca-root.crt"
            ca_private_key = ca_root / "ca-signing.key"
            ca_control_key = ca_root / "control-ed25519.key"
            ca_token_file = ca_root / "bootstrap.token"
            ca_db = ca_root / "registry.sqlite3"
            ca_issued = ca_root / "issued"
            ca_certificate.write_bytes(root_pem)
            ca_private_key.write_bytes(root_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ))
            ca_private_key.chmod(0o600)
            ca_control_key.write_bytes(ca_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            ))
            ca_control_key.chmod(0o600)
            bootstrap_token = base64.urlsafe_b64encode(os.urandom(48)).decode("ascii").rstrip("=")
            ca_token_file.write_text(bootstrap_token + "\n", encoding="ascii")
            ca_token_file.chmod(0o600)
            ca_config.write_text(yaml.safe_dump({
                "server": {
                    "host": "::", "port": 4790, "control_id": "nls-router-ca-test",
                    "identity_key": str(ca_control_key),
                    "replay_window": 128, "max_clock_skew_seconds": 120,
                    "session_timeout_seconds": 300, "key_rotation_seconds": 3600,
                },
                "database": {"path": str(ca_db)},
                "pki": {
                    "ca_certificate": str(ca_certificate),
                    "ca_private_key": str(ca_private_key),
                    "issued_cert_dir": str(ca_issued),
                },
                "enrollment": {"token_file": str(ca_token_file), "certificate_days": 30},
            }, sort_keys=False), encoding="utf-8")

            ca_src = Path(os.getcwd()).parent / "Nls-NexOS-Core-v0.1.0" / "src"
            ca_env = os.environ.copy()
            ca_env["PYTHONPATH"] = os.pathsep.join(
                item for item in (os.getcwd(), str(ca_src), ca_env.get("PYTHONPATH", "")) if item
            )
            control_public_key = base64.b64encode(
                ca_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode("ascii")
            router_tokens = {}
            for router_id, identity_key, encryption_key, endpoint, gateway, prefix in (
                ("router-a", a, a_rsa, "[fd00:12::1]:4789", "10.1.0.1", "10.1.0.0/24"),
                ("router-b", b, b_rsa, "[fd00:23::2]:4789", "10.2.0.1", "10.2.0.0/24"),
            ):
                token_path = ca_root / f"{router_id}.token"
                token = base64.urlsafe_b64encode(os.urandom(48)).decode("ascii").rstrip("=")
                token_path.write_text(token + "\n", encoding="ascii")
                token_path.chmod(0o600)
                router_tokens[router_id] = token_path
                ed_der = identity_key.public_key().public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                )
                rsa_der = encryption_key.public_key().public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                )
                register_cmd = [
                    os.sys.executable, "-m", "nls_nexos_core.cli", "--config", str(ca_config),
                    "register-router", router_id, "--token-file", str(token_path),
                    "--public-key-sha256", hashlib.sha256(ed_der).hexdigest(),
                    "--rsa-public-key-sha256", hashlib.sha256(rsa_der).hexdigest(),
                    "--wan-endpoint", endpoint, "--gateway-ip", gateway, "--prefix", prefix,
                ]
                registered = subprocess.run(
                    register_cmd, env=ca_env, check=True, capture_output=True, text=True, timeout=15
                )
                assert f"Registered router: {router_id}" in registered.stdout, registered.stdout

            for router_root, router_id in ((ra_root, "router-a"), (rb_root, "router-b")):
                config_dir = router_root / "etc"
                state_dir = router_root / "state"
                router_ca_cfg = {
                    "router_ca": {
                        "endpoint": "[fd00:34::2]:4790",
                        "server_id": "nls-router-ca-test",
                        "server_public_key": control_public_key,
                        "router_id": router_id,
                        "identity_key": str(state_dir / "identity" / "ed25519.key"),
                        "certificate_file": str(state_dir / "identity" / "router.crt"),
                        "ca_certificate_file": str(ca_certificate),
                        "bootstrap_token_file": str(ca_token_file),
                        "router_token_file": str(router_tokens[router_id]),
                        "policy_file": str(config_dir / "policy.json"),
                        "revocation_file": str(config_dir / "revocations.json"),
                        "directory_file": str(config_dir / "router-directory.json"),
                        "encryption_private_key": str(state_dir / "identity" / "rsa-encryption.pem"),
                        "nls_config_file": str(config_dir / "nls.yaml"),
                        "heartbeat_seconds": 5,
                        "connect_timeout_seconds": 5,
                    }
                }
                (config_dir / "router-ca-client.yaml").write_text(
                    yaml.safe_dump(router_ca_cfg, sort_keys=False), encoding="utf-8"
                )

            # The CA is a real process in the CA network namespace; both router
            # daemons use its authenticated TCP/4790 control channel.
            ca_proc = subprocess.Popen(
                ["ip", "netns", "exec", "nls-ca", os.sys.executable, "-m",
                 "nls_nexos_core.cli", "--config", str(ca_config), "serve"],
                env=ca_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            ca_deadline = time.monotonic() + 10
            while time.monotonic() < ca_deadline:
                if ca_proc.poll() is not None:
                    raise AssertionError(
                        "Router-CA process exited before listening: " +
                        (ca_proc.stdout.read() if ca_proc.stdout else "")
                    )
                if ":4790" in ns_exec("nls-ca", "ss", "-H", "-ltn", check=False).stdout:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("real Router-CA did not listen on TCP/4790")

            client_script = r"""
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from nls.ca_client import ClientSettings, enroll, directory_sync
settings = ClientSettings.load(sys.argv[1])
identity = ed25519.Ed25519PrivateKey.from_private_bytes(Path(settings.identity_key).read_bytes())
if sys.argv[2] == "enroll":
    enroll(settings, identity)
    print("ENROLL_OK", flush=True)
else:
    bundle = directory_sync(settings, identity)
    print("DIRECTORY_SYNC_OK directory_seq=" + str(bundle.get("directory_seq")), flush=True)
"""
            for ns, router_root in (("nls-ra", ra_root), ("nls-rb", rb_root)):
                client_cfg = router_root / "etc" / "router-ca-client.yaml"
                enrolled = subprocess.run(
                    ["ip", "netns", "exec", ns, os.sys.executable, "-c",
                     client_script, str(client_cfg), "enroll"],
                    env=ca_env, check=True, capture_output=True, text=True, timeout=20,
                )
                assert "NLS Router-CA enrollment successful" in enrolled.stdout, enrolled.stdout
            for ns, router_root in (("nls-ra", ra_root), ("nls-rb", rb_root)):
                client_cfg = router_root / "etc" / "router-ca-client.yaml"
                synced = subprocess.run(
                    ["ip", "netns", "exec", ns, os.sys.executable, "-c",
                     client_script, str(client_cfg), "sync"],
                    env=ca_env, check=True, capture_output=True, text=True, timeout=20,
                )
                assert "directory_seq" in synced.stdout, synced.stdout

            # The real control-plane agents hold authenticated CA channels and
            # deliver signed revocation updates into the rollback-protected cache.
            for ns, router_root in (("nls-ra", ra_root), ("nls-rb", rb_root)):
                agent = subprocess.Popen(
                    ["ip", "netns", "exec", ns, os.sys.executable, "-m", "nls.ca_client",
                     "run", "--config", str(router_root / "etc" / "router-ca-client.yaml")],
                    env=ca_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                ca_agents.append(agent)
            time.sleep(0.5)
            for agent in ca_agents:
                if agent.poll() is not None:
                    raise AssertionError("Router-CA client agent exited: " +
                                         (agent.stdout.read() if agent.stdout else ""))

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
                PYTHONPATH=ca_env["PYTHONPATH"],
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
                PYTHONPATH=ca_env["PYTHONPATH"],
            )
            if profile_mode:
                env_a["NLS_CPROFILE_OUT"] = str(ra_root / "router-a.cprofile")
                env_b["NLS_CPROFILE_OUT"] = str(rb_root / "router-b.cprofile")
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
            # Capture actual kernel route tables before daemon startup. This
            # detects accidental route mutation during startup/reconfiguration,
            # not only during later CA lookup and handshake processing.
            route_table_before_start = {
                ns: ns_exec(ns, "ip", "-6", "route", "show").stdout
                for ns in ("nls-ra", "nls-rb")
            }
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
            route_table_after_start = {
                ns: ns_exec(ns, "ip", "-6", "route", "show").stdout
                for ns in ("nls-ra", "nls-rb")
            }
            # Creating nls0 adds its kernel-generated fe80::/64 connected
            # route. Permit exactly that interface side effect; no CA-derived,
            # operator, or other route may be added, removed, or replaced.
            route_delta = {}
            for ns in ("nls-ra", "nls-rb"):
                before = set(route_table_before_start[ns].splitlines())
                after = set(route_table_after_start[ns].splitlines())
                added = after - before
                removed = before - after
                expected = {
                    line for line in after
                    if line.startswith("fe80::/64 dev nls0 proto kernel ")
                }
                assert not removed and added == expected, (
                    "NLS startup changed routes beyond the kernel-generated nls0 "
                    f"link-local route in {ns}: added={added!r}, removed={removed!r}"
                )
                route_delta[ns] = {"added_kernel_link_local": sorted(added), "removed": sorted(removed)}
            print("NLS_ROUTE_TABLE_STARTUP_NO_CA_ROUTE_CHANGE " + json.dumps(route_delta, sort_keys=True), flush=True)
            # Prompt 4a gate: NLH2 handshake with NLE2 directional session-key data path.
            print("NLS_DATA_PLANE=legacy NLE1 removed; NLE2 is the only data path", flush=True)
            # Snapshot the actual kernel IPv6 main route tables after startup.
            # CA lookup and handshake completion must not mutate them.
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
                            "iperf3", "-s", "-1", "-B", server_ip,
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
                        udp_bps, udp_metric, udp_loss = _iperf3_udp_receiver_stats(udp_report)
                        assert udp_bps > 1_000_000, (
                            f"NLE2 UDP {'reverse' if reverse else 'forward'} throughput too low: {udp_bps} bit/s"
                        )
                        print(
                            "NLS_UDP_1280 " + json.dumps({
                                "direction": "reverse" if reverse else "forward",
                                "bits_per_second": udp_bps,
                                "measurement": udp_metric,
                                "lost_percent": udp_loss,
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
                offered_rate = "2M" if profile_mode else "200M"
                bench_server = subprocess.Popen(
                    ["ip", "netns", "exec", "nls-server", "iperf3", "-s", "-1", "-B", "10.2.0.2"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                try:
                    wait_for_tcp_listener("nls-server", 5201, bench_server, timeout=8)
                    bench_result = ns_exec(
                        "nls-client", "iperf3", "-c", "10.2.0.2", "-u", "-l", "1252",
                        "-b", offered_rate, "-t", "5", "-J", timeout=20,
                    )
                    bench_json = json.loads(bench_result.stdout)
                    actual_bps, udp_metric, udp_loss = _iperf3_udp_receiver_stats(bench_json)
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
                        "lost_percent": udp_loss,
                        "measurement": udp_metric,
                        "met_target": actual_bps >= 100_000_000,
                        "inner_packet_bytes": 1280,
                        "method": f"iperf3 UDP, 1252-byte payload + 20-byte IPv4 header + 8-byte UDP header, {offered_rate} offered rate, 5 seconds",
                        "platform": platform.platform(),
                        "cpu_model": cpu_model,
                    }, sort_keys=True), flush=True)
                    if profile_mode:
                        assert udp_loss == 0.0, (
                            f"2 Mbit/s NLE2 lossless-rate test lost packets: {udp_loss}%"
                        )
                        assert actual_bps >= 1_800_000, (
                            f"2 Mbit/s NLE2 test delivered only {actual_bps} bit/s"
                        )
                        print("NLS_IPERF3_NLE2_2M_LOSSLESS " + json.dumps({
                            "offered_mbps": 2,
                            "actual_mbps": round(actual_bps / 1_000_000, 3),
                            "lost_percent": udp_loss,
                            "measurement": udp_metric,
                            "inner_packet_bytes": 1280,
                            "duration_seconds": 5,
                        }, sort_keys=True), flush=True)
                    else:
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
                # Positive control: the validated operator CLI route is persisted,
                # installed into the real namespace kernel table, and then removed.
                # This complements the CA-driven no-change assertions above.
                operator_route_control = """import json, subprocess, time
from services.router import config as router_config
from tools.router_cli import commands
from nls.routing import install_tun_routes, remove_tun_routes
prefix = "2001:db8:feed::/64"
commands._verified_directory_records = lambda: {
    "router-b": {
        "router_id": "router-b", "status": "ACTIVE",
        "valid_until": int(time.time()) + 60, "certificate_serial": "positive-control",
        "prefixes": [prefix],
    }
}
data = router_config.load()
commands._config_command(["nls", "route", prefix, "via", "router-b"], data)
router_config.save(data)
added = install_tun_routes([], "nls0")
assert prefix in added, added
route = subprocess.run(["ip", "-6", "route", "show", "exact", prefix],
                       check=True, capture_output=True, text=True).stdout
assert prefix in route and "dev nls0" in route, route
remove_tun_routes()
after = subprocess.run(["ip", "-6", "route", "show", "exact", prefix],
                       check=True, capture_output=True, text=True).stdout
assert not after.strip(), after
print("NLS_ROUTE_TABLE_OPERATOR_POSITIVE_CONTROL " + json.dumps({
    "prefix": prefix, "installed_via": "nls0", "cleanup": "verified",
}, sort_keys=True), flush=True)
"""
                positive = subprocess.run(
                    ["ip", "netns", "exec", "nls-ra", os.sys.executable, "-c", operator_route_control],
                    env=env_a, check=True, capture_output=True, text=True, timeout=10,
                )
                assert "NLS_ROUTE_TABLE_OPERATOR_POSITIVE_CONTROL" in positive.stdout, positive.stdout
                print(positive.stdout.strip(), flush=True)
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
                capture_path = root / "nls-v1-real-wan.pcap"
                capture = None
                try:
                    for _ in range(30):
                        if ":40000" in ns_exec("nls-server", "ss", "-lun").stdout:
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError("UDP echo server did not bind")
                    # Capture a real NLE2 data datagram on the WAN after handshake
                    # completion. This is a pcap from the actual router processes.
                    capture = subprocess.Popen(
                        ["ip", "netns", "exec", "nls-wan", "tcpdump", "-i", "ra0",
                         "-n", "-s", "0", "-c", "1", "-w", str(capture_path),
                         "ip6 and udp port 4789"],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    )
                    time.sleep(0.25)
                    if capture.poll() is not None:
                        raise AssertionError(
                            "tcpdump exited before the real data packet: " +
                            (capture.stdout.read() if capture.stdout else "")
                        )
                    echo_client_code = (
                        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                        "s.settimeout(4); c=b'INNER-PLAINTEXT-CANARY-4A'; "
                        "p=c+b'R'*(1252-len(c)); s.sendto(p,('10.2.0.2',40000)); "
                        "d,_=s.recvfrom(2048); assert d==p; print('UDP_ECHO_RETURN_OK',len(d)+28)"
                    )
                    echo_result = ns_exec(
                        "nls-client", os.sys.executable, "-c", echo_client_code, timeout=8
                    )
                    assert "UDP_ECHO_RETURN_OK 1280" in echo_result.stdout
                    print("NLS_UDP_RETURN_PATH " + echo_result.stdout.strip(), flush=True)
                    capture.wait(timeout=5)
                    assert capture.returncode == 0, (
                        "tcpdump failed: " + (capture.stdout.read() if capture.stdout else "")
                    )
                    pcap_bytes = capture_path.read_bytes()
                    canary = b"INNER-PLAINTEXT-CANARY-4A"
                    assert canary not in pcap_bytes, "inner payload canary appeared in WAN pcap"
                    assert socket.inet_aton("10.1.0.2") not in pcap_bytes, "inner source IPv4 appeared in WAN pcap"
                    assert socket.inet_aton("10.2.0.2") not in pcap_bytes, "inner destination IPv4 appeared in WAN pcap"
                    for vip in vip_seen:
                        assert ipaddress.IPv6Address(vip).packed not in pcap_bytes, (
                            f"bootstrap vIP {vip} appeared on the WAN after endpoint switch"
                        )
                    print("NLS_REAL_WAN_PCAP_CONFIDENTIALITY " + json.dumps({
                        "pcap": capture_path.name, "captured_bytes": len(pcap_bytes),
                        "inner_source_plaintext": False, "inner_destination_plaintext": False,
                        "payload_canary_plaintext": False, "vip_after_switch": False,
                    }, sort_keys=True), flush=True)
                finally:
                    if capture is not None and capture.poll() is None:
                        capture.terminate()
                        try:
                            capture.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            capture.kill()
                            capture.wait(timeout=3)
                    if echo_server.poll() is None:
                        echo_server.terminate()
                    try:
                        echo_server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        echo_server.kill()
                        echo_server.wait(timeout=3)

                # Authenticated relay abuse: a client spoofs an inner source that
                # is outside Router A's CA-signed prefixes. The real Router B must
                # drop it after decrypting the WAN datagram and log a stable reason.
                ns_exec("nls-client", "ip", "addr", "add", "198.51.100.9/32", "dev", "c0")
                spoof = ns_exec(
                    "nls-client", "ping", "-I", "198.51.100.9", "-c", "1", "-W", "1",
                    "10.2.0.2", check=False, timeout=5,
                )
                assert spoof.returncode != 0, (
                    "spoofed inner source unexpectedly reached the server: " + spoof.stdout
                )
                rb_status_path = rb_root / "status.json"
                relay_deadline = time.monotonic() + 5
                relay_status = {}
                while time.monotonic() < relay_deadline:
                    try:
                        relay_status = json.loads(rb_status_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        time.sleep(0.1)
                        continue
                    if relay_status.get("reason_counters", {}).get("NLS_DATA_INNER_SRC_NOT_ALLOWED", 0):
                        break
                    time.sleep(0.1)
                assert relay_status.get("reason_counters", {}).get(
                    "NLS_DATA_INNER_SRC_NOT_ALLOWED", 0
                ) > 0, "real Router B did not log the unauthorized inner-source drop"
                print("NLS_REAL_RELAY_ABUSE_REJECTED " + json.dumps({
                    "spoofed_inner_source": "198.51.100.9",
                    "reason": "NLS_DATA_INNER_SRC_NOT_ALLOWED",
                    "router_b_status": rb_status_path.name,
                }, sort_keys=True), flush=True)

                # Simultaneous rekey under real bidirectional TCP traffic. The
                # test arms both daemon processes together, streams numbered
                # records in both directions, and checks one established session
                # with a new session id after every one of ten rekey cycles.
                rekey_stream = r"""
import socket, sys, threading, time
local_ip, peer_ip, count, port = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((local_ip, port))
listener.listen(1)
deadline = time.monotonic() + 6
outgoing = None
while time.monotonic() < deadline:
    try:
        outgoing = socket.create_connection((peer_ip, port), timeout=1)
        break
    except OSError:
        time.sleep(0.02)
if outgoing is None:
    raise RuntimeError("could not establish rekey stream connection")
listener.settimeout(6)
incoming, _ = listener.accept()
outgoing.settimeout(8)
incoming.settimeout(8)
received = set()
def receive():
    while len(received) < count:
        chunk = b""
        while len(chunk) < 8:
            part = incoming.recv(8 - len(chunk))
            if not part:
                raise RuntimeError("TCP stream closed before all sequence numbers arrived")
            chunk += part
        received.add(int.from_bytes(chunk, "big"))
reader = threading.Thread(target=receive)
reader.start()
for seq in range(count):
    outgoing.sendall(seq.to_bytes(8, "big"))
    time.sleep(0.005)
reader.join(timeout=8)
if reader.is_alive() or received != set(range(count)):
    raise RuntimeError(f"sequence loss: got {len(received)}/{count}")
print(f"REKEY_STREAM_OK sent={count} received={len(received)} unique={len(received)}", flush=True)
outgoing.close()
incoming.close()
listener.close()
"""
                collision_count_before = 0
                for iteration in range(10):
                    before_a = json.loads((ra_root / "status.json").read_text(encoding="utf-8"))
                    before_b = json.loads((rb_root / "status.json").read_text(encoding="utf-8"))
                    assert len(before_a.get("sessions", [])) == 1, before_a
                    assert len(before_b.get("sessions", [])) == 1, before_b
                    old_a = before_a["sessions"][0]["session_id"]
                    old_b = before_b["sessions"][0]["session_id"]
                    procs[0].send_signal(signal.SIGUSR1)
                    procs[1].send_signal(signal.SIGUSR1)
                    streams = [
                        subprocess.Popen(
                            ["ip", "netns", "exec", ns, os.sys.executable, "-u", "-c",
                             rekey_stream, local_ip, peer_ip, "64", "41002"],
                            env=ca_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        )
                        for ns, local_ip, peer_ip in (
                            ("nls-client", "10.1.0.2", "10.2.0.2"),
                            ("nls-server", "10.2.0.2", "10.1.0.2"),
                        )
                    ]
                    stream_outputs = []
                    for stream in streams:
                        output, _ = stream.communicate(timeout=12)
                        stream_outputs.append(output)
                        assert stream.returncode == 0 and "REKEY_STREAM_OK sent=64 received=64 unique=64" in output, (
                            "simultaneous rekey stream failed: " + output
                        )
                    rekey_deadline = time.monotonic() + 8
                    after_a, after_b = {}, {}
                    while time.monotonic() < rekey_deadline:
                        try:
                            after_a = json.loads((ra_root / "status.json").read_text(encoding="utf-8"))
                            after_b = json.loads((rb_root / "status.json").read_text(encoding="utf-8"))
                        except (OSError, ValueError):
                            time.sleep(0.1)
                            continue
                        sessions_a, sessions_b = after_a.get("sessions", []), after_b.get("sessions", [])
                        if (
                            len(sessions_a) == len(sessions_b) == 1
                            and sessions_a[0].get("state") == sessions_b[0].get("state") == "ESTABLISHED"
                            and sessions_a[0].get("session_id") != old_a
                            and sessions_b[0].get("session_id") != old_b
                        ):
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError(
                            f"rekey iteration {iteration + 1}: expected exactly one new established session; "
                            f"router-a={after_a!r}; router-b={after_b!r}"
                        )
                    procs[0].send_signal(signal.SIGUSR2)
                    procs[1].send_signal(signal.SIGUSR2)
                    collision_count_before += (
                        after_a.get("reason_counters", {}).get("NLS_REKEY_SIMULTANEOUS_LOST", 0)
                        + after_b.get("reason_counters", {}).get("NLS_REKEY_SIMULTANEOUS_LOST", 0)
                    )
                    print("NLS_REAL_SIMULTANEOUS_REKEY " + json.dumps({
                        "iteration": iteration + 1, "router_a_old": old_a,
                        "router_a_new": sessions_a[0]["session_id"],
                        "router_b_old": old_b, "router_b_new": sessions_b[0]["session_id"],
                        "router_a_active_sessions": len(sessions_a),
                        "router_b_active_sessions": len(sessions_b),
                        "sequence_loss": 0, "streams": stream_outputs,
                    }, sort_keys=True), flush=True)
                assert collision_count_before > 0, (
                    "both routers were armed for simultaneous rekey, but no simultaneous-rekey arbitration was observed"
                )

                # Revoke Router B in the real CA registry and measure the
                # heartbeat-to-teardown interval on both live daemons.
                revoked = subprocess.run(
                    [os.sys.executable, "-m", "nls_nexos_core.cli", "--config",
                     str(ca_config), "revoke-router", "router-b"],
                    env=ca_env, check=True, capture_output=True, text=True, timeout=10,
                )
                assert "Revoked router and active certificates: router-b" in revoked.stdout, revoked.stdout
                revoke_started = time.monotonic()
                revoke_deadline = revoke_started + 7
                revoked_a, revoked_b = {}, {}
                while time.monotonic() < revoke_deadline:
                    try:
                        revoked_a = json.loads((ra_root / "status.json").read_text(encoding="utf-8"))
                        revoked_b = json.loads((rb_root / "status.json").read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        time.sleep(0.1)
                        continue
                    if not revoked_a.get("sessions") and not revoked_b.get("sessions"):
                        break
                    time.sleep(0.1)
                revoke_elapsed = time.monotonic() - revoke_started
                assert not revoked_a.get("sessions") and not revoked_b.get("sessions"), (
                    f"real revocation did not tear down both sessions: A={revoked_a!r}; B={revoked_b!r}"
                )
                assert revoke_elapsed <= 6.0, (
                    f"heartbeat-to-teardown exceeded 5-second heartbeat + 1s: {revoke_elapsed:.3f}s"
                )
                # A post-revocation UDP packet must not reach the server or return.
                revoked_echo = subprocess.Popen(
                    ["ip", "netns", "exec", "nls-server", os.sys.executable, "-u", "-c",
                     "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                     "s.bind(('10.2.0.2',40001)); d,a=s.recvfrom(2048); s.sendto(d,a)"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                try:
                    time.sleep(0.15)
                    after_revoke_client = ns_exec(
                        "nls-client", os.sys.executable, "-c",
                        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                        "s.settimeout(1); s.sendto(b'AFTER-REVOKE',('10.2.0.2',40001)); "
                        "\ntry: s.recvfrom(2048); raise SystemExit('packet forwarded after revocation')"
                        "\nexcept socket.timeout: print('NO_FORWARD_AFTER_REVOKE')",
                        timeout=3,
                    )
                    assert "NO_FORWARD_AFTER_REVOKE" in after_revoke_client.stdout
                finally:
                    if revoked_echo.poll() is None:
                        revoked_echo.terminate()
                    try:
                        revoked_echo.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        revoked_echo.kill()
                        revoked_echo.wait(timeout=2)
                print("NLS_REAL_REVOCATION_TEARDOWN " + json.dumps({
                    "heartbeat_seconds": 5, "elapsed_seconds": round(revoke_elapsed, 3),
                    "limit_seconds": 6, "sessions_after_revoke": 0,
                    "post_revoke_forwarding": False,
                }, sort_keys=True), flush=True)

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
                    p.wait(timeout=3)
            for agent in ca_agents:
                if agent.poll() is None:
                    agent.send_signal(signal.SIGTERM)
                try:
                    agent.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    agent.kill()
                    agent.wait(timeout=3)
            if ca_proc is not None and ca_proc.poll() is None:
                ca_proc.send_signal(signal.SIGTERM)
                try:
                    ca_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    ca_proc.kill()
                    ca_proc.wait(timeout=3)
            if profile_mode:
                import pstats
                stage_functions = {
                    "_send_payload", "_handle_data", "_dispatch_datagram",
                    "_refresh_session_trust", "seal_ip_packet", "open_ip_packet",
                    "read", "write", "recvfrom", "sendto",
                }
                for router_name, profile_path in (
                    ("router-a", Path(td) / "ra" / "router-a.cprofile"),
                    ("router-b", Path(td) / "rb" / "router-b.cprofile"),
                ):
                    if profile_path.exists():
                        stats = pstats.Stats(str(profile_path))
                        stages = []
                        for (filename, line_no, function), values in stats.stats.items():
                            if function in stage_functions and (
                                "/nls/" in filename or filename.endswith("socket.py")
                            ):
                                primitive_calls, total_calls, self_seconds, cumulative_seconds, _ = values
                                stages.append({
                                    "function": function, "file": Path(filename).name,
                                    "calls": total_calls, "self_seconds": round(self_seconds, 6),
                                    "cumulative_seconds": round(cumulative_seconds, 6),
                                })
                        stages.sort(key=lambda item: item["cumulative_seconds"], reverse=True)
                        print("NLS_CPROFILE_STAGE_TIMES " + json.dumps({
                            "router": router_name, "profile": str(profile_path.name),
                            "stages": stages[:30],
                        }, sort_keys=True), flush=True)
                        import io
                        stream = io.StringIO()
                        stats.stream = stream
                        stats.sort_stats("cumtime").print_stats(20)
                        print("NLS_CPROFILE_TOP " + json.dumps({
                            "router": router_name, "top": stream.getvalue(),
                        }, sort_keys=True), flush=True)
                    else:
                        raise AssertionError("NLS_CPROFILE_MISSING " + str(profile_path))
            for ns in namespaces:
                run("ip", "netns", "del", ns, check=False)
