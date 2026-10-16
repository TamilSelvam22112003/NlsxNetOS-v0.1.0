from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from nls import ca_client
from nls.daemon import NLSDaemon
from nls.handshake import M1, V2_HEADER, V2_MAGIC, V2_VERSION, encode_v2_message, sign_v2
from nls.key_schedule import derive_session_keys, transcript_hash
from nls import routing
from nls.routing import install_tun_routes
from nls.v2_runtime import HandshakeV2, M2_MAX_DATAGRAM, SUITE
from nls.vip import VIPManager
from services.router import config as router_config


def _owner(rsa_private=None):
    return SimpleNamespace(
        cfg=SimpleNamespace(bind_interface="", router_id="router-s", replay_window=64),
        stats={"drops": 0, "data_drops": 0, "handshakes": 0, "established": 0},
        sessions={}, peers={}, pending_payloads={}, blocked={},
        identity=ed25519.Ed25519PrivateKey.generate(),
        encryption_private_key=rsa_private or rsa.generate_private_key(public_exponent=65537, key_size=3072),
        _flush_pending=lambda _peer: None,
    )


def _root_cert(root_key, name="NLS Test Root", serial=0x1000, days=365):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(root_key.public_key()).serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )


def _leaf_cert(identity, root_key, root_cert, router_id="router-s", serial=0x1234, expired=False):
    now = datetime.now(timezone.utc)
    before = now - timedelta(days=10)
    after = now - timedelta(days=1) if expired else now + timedelta(days=10)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, router_id)]))
        .issuer_name(root_cert.subject).public_key(identity.public_key()).serial_number(serial)
        .not_valid_before(before).not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(root_key, hashes.SHA256())
    )


def _record(identity, rsa_private, serial="1234"):
    raw = identity.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    rsa_pem = rsa_private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    now = int(time.time())
    return {
        "router_id": "router-s",
        "ed25519_public_key": base64.b64encode(raw).decode("ascii"),
        "rsa_encryption_public_key": rsa_pem,
        "wan_endpoints": ["[2001:db8::10]:4789"],
        "gateway_ips": [],
        "prefixes": ["2001:db8:100::/48"],
        "certificate_serial": serial,
        "status": "ACTIVE",
        "record_seq": 1,
        "issued_at": now,
        "valid_until": now + 20,
    }


def _runtime(settings=None, rsa_private=None):
    owner = _owner(rsa_private)
    runtime = HandshakeV2(owner)
    runtime.settings = settings
    return owner, runtime


def test_wrong_certificate_chain_rejected(tmp_path):
    trusted_root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    wrong_root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    trusted_root = _root_cert(trusted_root_key)
    wrong_root = _root_cert(wrong_root_key, name="Wrong Root", serial=0x2000)
    identity = ed25519.Ed25519PrivateKey.generate()
    leaf = _leaf_cert(identity, wrong_root_key, wrong_root, serial=0x1234)
    root_path = tmp_path / "trusted-root.pem"
    root_path.write_bytes(trusted_root.public_bytes(serialization.Encoding.PEM))
    _, runtime = _runtime(SimpleNamespace(ca_certificate_file=root_path))
    record = _record(identity, rsa.generate_private_key(public_exponent=65537, key_size=3072))
    with pytest.raises(ValueError, match="certificate validation failed"):
        runtime._certificate(leaf.public_bytes(serialization.Encoding.PEM), record)


@pytest.mark.parametrize("stage", ["S3", "S4"])
def test_revoked_router_rejected_s3_s4(monkeypatch, stage):
    identity = ed25519.Ed25519PrivateKey.generate()
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    record = _record(identity, encryption)
    _, runtime = _runtime(SimpleNamespace())
    monkeypatch.setattr(ca_client, "is_revoked", lambda _serial, _settings: True)
    with pytest.raises(ValueError, match="revoked"):
        runtime._validate_record(record, fresh=True)


def test_expired_certificate_rejected(tmp_path):
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    root = _root_cert(root_key)
    identity = ed25519.Ed25519PrivateKey.generate()
    leaf = _leaf_cert(identity, root_key, root, serial=0x1234, expired=True)
    root_path = tmp_path / "root.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    _, runtime = _runtime(SimpleNamespace(ca_certificate_file=root_path))
    record = _record(identity, rsa.generate_private_key(public_exponent=65537, key_size=3072))
    with pytest.raises(ValueError, match="certificate validation failed"):
        runtime._certificate(leaf.public_bytes(serialization.Encoding.PEM), record)


@pytest.mark.parametrize("stage", ["S3", "S4"])
def test_ca_mismatch_rejected_in_s3_s4(stage):
    identity = ed25519.Ed25519PrivateKey.generate()
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    record = _record(identity, encryption)
    changed = dict(record)
    changed["wan_endpoints"] = ["[2001:db8::99]:4789"]
    _, runtime = _runtime(SimpleNamespace())
    with pytest.raises(ValueError, match=f"NLS_HS_CA_MISMATCH_{stage}"):
        runtime.compare_fresh_record(changed, record, stage)


def test_sa_downgrade_rejected():
    _, runtime = _runtime(SimpleNamespace())
    policy = {"allowed_suites": [SUITE]}
    with pytest.raises(ValueError, match="NLS_HS_SA_DOWNGRADE"):
        runtime.validate_suite("RSA-PER-PACKET-LEGACY", [SUITE], policy)
    with pytest.raises(ValueError, match="NLS_HS_SA_PROPOSAL_MISMATCH"):
        runtime.validate_suite(SUITE, ["RSA-PER-PACKET-LEGACY"], policy)


def test_out_of_order_handshake_message_is_dropped():
    owner, runtime = _runtime()
    sid = os.urandom(16)
    envelope = os.urandom(500)
    packet = V2_HEADER.pack(V2_MAGIC, V2_VERSION, 2, sid, len(envelope)) + envelope
    runtime.handle_packet(packet, ("2001:db8::20", 4789, 0, 0))
    assert sid not in runtime.pending
    assert owner.stats["drops"] >= 1


def test_wrong_key_m1_is_screened_before_allocating_pending_state(monkeypatch):
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    owner, runtime = _runtime(rsa_private=rsa_private)
    attacker = ed25519.Ed25519PrivateKey.generate()
    legitimate = ed25519.Ed25519PrivateKey.generate()
    record = _record(legitimate, rsa_private)
    monkeypatch.setattr(runtime, "_cached_record", lambda _router_id: record)
    sid = os.urandom(16)
    attacker_raw = attacker.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    obj = {
        "session_id": sid, "router_id": "router-s",
        "ed25519_public_key": attacker_raw,
        "rsa_encryption_public_key": rsa_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        "nonce_s": os.urandom(32), "timestamp": int(time.time()),
        "vip": "fd42:4e4c:53::1234", "padding": os.urandom(7600),
    }
    packet = encode_v2_message(M1, sid, rsa_private.public_key(), sign_v2(M1, obj, attacker))
    runtime._handle_m1(packet, ("fd42:4e4c:53::1234", 4789, 0, 0), sid)
    assert sid not in runtime.pending
    assert owner.stats["handshakes"] == 0


def test_garbage_m1_does_not_block_a_router_identity():
    owner, runtime = _runtime()
    owner.blocked = {}
    runtime.handle_packet(b"NLH2-not-a-valid-datagram", ("2001:db8::20", 4789, 0, 0))
    assert owner.blocked == {}
    assert runtime._allow_source(("2001:db8::20", 4789, 0, 0))


def test_m1_padding_covers_maximum_m2_amplification_budget():
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    identity = ed25519.Ed25519PrivateKey.generate()
    sid = os.urandom(16)
    raw = identity.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    obj = {
        "session_id": sid, "router_id": "router-s",
        "ed25519_public_key": raw,
        "rsa_encryption_public_key": rsa_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        "nonce_s": os.urandom(32), "timestamp": int(time.time()),
        "vip": "fd42:4e4c:53::1234", "padding": os.urandom(7600),
    }
    packet = encode_v2_message(M1, sid, rsa_private.public_key(), sign_v2(M1, obj, identity))
    assert len(packet) >= M2_MAX_DATAGRAM


def test_vip_expiry_removes_address_and_clears_ownership(monkeypatch, tmp_path):
    calls = []
    assigned = []
    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[:4] == ["ip", "-6", "addr", "add"]:
            assigned.append(args[4].split("/")[0])
        if args[:5] == ["ip", "-6", "addr", "show", "dev"]:
            output = "\n".join(f"inet6 {address}/128 scope global" for address in assigned)
            return subprocess.CompletedProcess(args, 0, output, "")
        if args[:4] == ["ip", "-6", "addr", "del"] and len(args) > 4:
            assigned[:] = [value for value in assigned if value != args[4].split("/")[0]]
        return subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("nls.vip.secrets.randbits", lambda _bits: 0x1234)
    manager = VIPManager("wan0", state_path=tmp_path / "vip-state.json", ttl=10)
    address = manager.allocate()
    deadline = manager.active[address]
    assert address in manager.active
    expired = manager.expire(now=deadline + 0.01)
    assert address in expired
    assert address not in manager.active
    reused = manager.allocate()
    assert reused == address, "an expired vIP must become eligible for reuse"
    manager.release(reused)
    assert any(call[:4] == ["ip", "-6", "addr", "del"] for call in calls)
    assert json.loads((tmp_path / "vip-state.json").read_text())["addresses"] == []


def test_retired_vip_data_packet_is_dropped_with_reason_code(caplog):
    owner, runtime = _runtime()
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.stats = {"drops": 0, "data_drops": 0}
    daemon.v2 = runtime
    vip = "fd42:4e4c:53::1234"
    runtime.retired_vips[vip] = time.monotonic() + 30
    caplog.set_level(logging.WARNING, logger="nlsxnetos.nls")
    daemon._handle_data(b"not-a-data-packet", (vip, 4789, 0, 0))
    assert daemon.stats["drops"] == 1
    assert "VIP_AFTER_SWITCH" in caplog.text


def test_routes_not_created_from_ca_peer_prefixes(monkeypatch, tmp_path):
    monkeypatch.setattr(router_config, "PATH", tmp_path / "router.yaml")
    monkeypatch.setattr(routing, "STATE_PATH", tmp_path / "nls-routes.json")
    (tmp_path / "router.yaml").write_text(
        "router:\n  interfaces: {}\n  nls_routes: []\n", encoding="utf-8"
    )
    calls = []
    monkeypatch.setattr("nls.routing._add_endpoint_host_route", lambda *_args: None)
    monkeypatch.setattr("nls.routing._exact_route_exists", lambda _prefix: False)
    monkeypatch.setattr("nls.routing._run", lambda args: calls.append(list(args)))
    peer = SimpleNamespace(endpoint="[2001:db8::2]:4789", allowed_prefixes=["2001:db8:200::/48"])
    assert install_tun_routes([peer], "nls0", routes=[]) == []
    assert not any("2001:db8:200::/48" in call for call in calls)


def test_logs_redact_keys_tokens_and_plaintext_canaries(caplog):
    owner, runtime = _runtime()
    owner.secret_token = "TOKEN-CANARY-DO-NOT-LOG"
    owner.plaintext_canary = "PLAINTEXT-CANARY-DO-NOT-LOG"
    owner.private_key_canary = "PRIVATE-KEY-CANARY-DO-NOT-LOG"
    caplog.set_level(logging.WARNING, logger="nlsxnetos.nls")
    runtime._drop("NLS_HS_MALFORMED", ("2001:db8::20", 4789, 0, 0), "S2")
    log_text = caplog.text
    assert "NLS_HS_MALFORMED" in log_text
    assert "TOKEN-CANARY-DO-NOT-LOG" not in log_text
    assert "PLAINTEXT-CANARY-DO-NOT-LOG" not in log_text
    assert "PRIVATE-KEY-CANARY-DO-NOT-LOG" not in log_text


def test_v2_transcript_and_directional_keys_match():
    from cryptography.hazmat.primitives.asymmetric import x25519
    a = x25519.X25519PrivateKey.generate()
    b = x25519.X25519PrivateKey.generate()
    ap = a.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    bp = b.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sid = os.urandom(16)
    h3 = transcript_hash(b"m1", b"m2", b"m3")
    a_keys = derive_session_keys(a, bp, h3, sid)
    b_keys = derive_session_keys(b, ap, h3, sid)
    assert a_keys == b_keys


def test_handshake_fails_closed_when_ca_is_unreachable(monkeypatch):
    owner, runtime = _runtime(SimpleNamespace())
    sid = os.urandom(16)
    runtime.pending[sid] = {
        "role": "S", "state": "M1_SENT", "peer_id": "router-d",
        "m1_plain": b"test-transcript", "peer_endpoint": "[2001:db8::20]:4789",
    }
    monkeypatch.setattr(
        "nls.v2_runtime.open_v2_message",
        lambda *_args: (2, sid, {"router_id": "router-d"}, b"m2"),
    )
    def unreachable(*_args, **_kwargs):
        raise OSError("Router-CA unavailable")
    monkeypatch.setattr(ca_client, "lookup", unreachable)
    runtime._handle_m2(b"test", ("2001:db8::20", 4789, 0, 0), sid)
    assert sid not in runtime.pending
    assert sid not in owner.sessions
    assert owner.stats["drops"] >= 1


def test_forged_ca_lookup_envelope_is_rejected(monkeypatch):
    identity = ed25519.Ed25519PrivateKey.generate()
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    record = _record(identity, encryption)
    owner, runtime = _runtime(SimpleNamespace())
    monkeypatch.setattr(ca_client, "lookup", lambda *_args: record)
    monkeypatch.setattr(ca_client, "lookup_envelope", lambda *_args: {
        "encoding": "canonical-cbor", "domain": "NLS-DIR-v1",
        "payload": record, "signer_public_key": "AAAA", "signature": "AAAA",
    })
    with pytest.raises(Exception):
        runtime._record_envelope("router-s")
