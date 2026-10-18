import base64
import json
import shutil
import subprocess
from dataclasses import replace
import time

import cbor2
import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nls.ca_client import (
    ClientSettings, _DIRECTORY_DOMAIN, _load_verified_cache, _save_verified_cache,
    _validate_lookup_response, _verify_directory_envelope, directory_freshness, is_revoked,
)


def _envelope(payload, key):
    payload = dict(payload)
    if "router_id" in payload:
        # Minimal security-test RDRs model retained legacy rows: signed, v2, but unusable.
        payload.setdefault("rdr_version", 2)
        payload.setdefault("wan_endpoints", [])
        payload.setdefault("originalIP", None)
        payload.setdefault("original_ip_usable", False)
        payload.setdefault("ed25519_public_key", None)
        payload.setdefault("ed25519_public_key_spki_der_b64", None)
        payload.setdefault("certificate_der_b64", None)
        payload.setdefault("rsa_encryption_public_key", None)
        payload.setdefault("certificate_serial", None)
        payload.setdefault("record_seq", 1)
        payload.setdefault("issued_at", int(time.time()))
        payload.setdefault("valid_until", int(time.time()) + 20)
        payload.setdefault("status", "UNKNOWN")
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    import hashlib
    return {
        "payload": payload,
        "signer_public_key": base64.b64encode(raw).decode(),
        "signature": base64.b64encode(key.sign(_DIRECTORY_DOMAIN + cbor2.dumps(payload, canonical=True))).decode(),
        "encoding": "canonical-cbor",
        "domain": "NLS-DIR-v1",
    }


def _settings(tmp_path, key):
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return ClientSettings(
        endpoint="[::1]:4790", server_id="ca-test",
        server_public_key=base64.b64encode(public).decode(), router_id="router-a",
        identity_key=tmp_path / "identity.key", certificate_file=tmp_path / "router.crt",
        ca_certificate_file=tmp_path / "root.crt", bootstrap_token_file=tmp_path / "bootstrap.token",
        router_token_file=tmp_path / "router.token", policy_file=tmp_path / "policy.json",
        revocation_file=tmp_path / "revocations.json", directory_file=tmp_path / "directory.json",
    )


def test_signed_lookup_envelope_and_nonce_record_shape(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    record = {"router_id": "router-b", "record_seq": 2, "status": "ACTIVE",
              "valid_until": int(time.time()) + 20}
    envelope = _envelope(record, key)
    assert _verify_directory_envelope(envelope, settings)["router_id"] == "router-b"


def test_forged_directory_signature_is_rejected(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    envelope = _envelope({"router_id": "router-b"}, key)
    envelope["payload"]["router_id"] = "attacker"
    with pytest.raises(RuntimeError, match="signature verification failed"):
        _verify_directory_envelope(envelope, settings)


def test_cache_rejects_directory_sequence_rollback(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    now = int(time.time())
    newer = _envelope({"directory_seq": 8, "expires_at": now + 300, "records": [],
                       "revoked_serials": []}, key)
    older = _envelope({"directory_seq": 7, "expires_at": now + 300, "records": [],
                       "revoked_serials": []}, key)
    _save_verified_cache(settings, bundle=newer, lookups={})
    with pytest.raises(RuntimeError, match="rollback"):
        _save_verified_cache(settings, bundle=older, lookups={})


def test_expired_cache_fails_closed_for_revocation_state(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    now = int(time.time())
    bundle = _envelope({"directory_seq": 1, "expires_at": now + 300,
                        "records": [], "revoked_serials": ["a1"]}, key)
    _save_verified_cache(settings, bundle=bundle, lookups={})
    monkeypatch.setattr("nls.ca_client.time.time", lambda: now + 301)
    assert directory_freshness(settings) == -1
    with pytest.raises(RuntimeError, match="freshness expired"):
        is_revoked("a1", settings)


def test_cache_is_reverified_on_every_read(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    bundle = _envelope({"directory_seq": 1, "expires_at": int(time.time()) + 300,
                        "records": [], "revoked_serials": []}, key)
    _save_verified_cache(settings, bundle=bundle, lookups={})
    cache = json.loads(settings.directory_file.read_text())
    cache["bundle"]["payload"]["directory_seq"] = 99
    settings.directory_file.write_text(json.dumps(cache))
    with pytest.raises(RuntimeError, match="signature verification failed"):
        _load_verified_cache(settings)



def test_lookup_rejects_wrong_nonce_and_expired_validity(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    now = int(time.time())
    nonce = "n" * 43
    wrong = _envelope({"router_id": "router-b", "record_seq": 1, "status": "ACTIVE",
                       "valid_until": now + 20, "client_nonce": "x" * 43}, key)
    response = {"type": "lookup-result", "client_nonce": nonce, "record": wrong}
    with pytest.raises(RuntimeError, match="nonce is not bound"):
        _validate_lookup_response(response, nonce, settings)
    expired = _envelope({"router_id": "router-b", "record_seq": 1, "status": "EXPIRED",
                         "valid_until": now - 1, "client_nonce": nonce}, key)
    with pytest.raises(RuntimeError, match="freshness invalid"):
        _validate_lookup_response({"type": "lookup-result", "client_nonce": nonce,
                                   "record": expired}, nonce, settings)


def test_lookup_rejects_wrong_signer(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    other = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    nonce = "z" * 43
    envelope = _envelope({"router_id": "router-b", "record_seq": 1, "status": "ACTIVE",
                          "valid_until": int(time.time()) + 20, "client_nonce": nonce}, other)
    with pytest.raises(RuntimeError, match="signature verification failed"):
        _validate_lookup_response({"type": "lookup-result", "client_nonce": nonce,
                                   "record": envelope}, nonce, settings)



def test_signed_bundle_import_kernel_route_table_snapshot_and_rollback(tmp_path, monkeypatch):
    from security.trust.router_ca import store
    routes_before = _kernel_ipv6_route_snapshot()
    key = ed25519.Ed25519PrivateKey.generate()
    pinned = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    config = tmp_path / "router-ca-client.yaml"
    config.write_text("router_ca:\n  server_public_key: '" + base64.b64encode(pinned).decode() + "'\n")
    monkeypatch.setattr(store, "CLIENT_CONFIG", config)
    monkeypatch.setattr(store, "CACHE_PATH", tmp_path / "cache" / "directory.json")
    now = int(time.time())
    record = _envelope({"router_id": "router-a", "record_seq": 1, "status": "ACTIVE",
                        "valid_until": now + 300, "wan_endpoints": [], "prefixes": [],
                        "gateway_ips": [], "ed25519_public_key": None,
                        "rsa_encryption_public_key": None, "certificate_serial": "a1",
                        "issued_at": now}, key)
    good = _envelope({"directory_seq": 4, "expires_at": now + 300, "issued_at": now,
                       "records": [record], "revoked_serials": [], "policy": {}}, key)
    source = tmp_path / "bundle.json"
    source.write_text(json.dumps(good))
    imported = store.import_bundle(source)
    assert imported["directory_seq"] == 4
    _, loaded = store.verified_bundle()
    assert loaded["directory_seq"] == 4

    tampered = json.loads(json.dumps(good))
    tampered["payload"]["directory_seq"] = 5
    source.write_text(json.dumps(tampered))
    with pytest.raises(RuntimeError, match="signature verification failed"):
        store.import_bundle(source)

    wrong_signer = _envelope({"directory_seq": 5, "expires_at": now + 300,
                              "records": [], "revoked_serials": [], "policy": {}},
                             ed25519.Ed25519PrivateKey.generate())
    source.write_text(json.dumps(wrong_signer))
    with pytest.raises(RuntimeError, match="signature verification failed"):
        store.import_bundle(source)

    expired = _envelope({"directory_seq": 5, "expires_at": now - 1,
                         "records": [], "revoked_serials": [], "policy": {}}, key)
    source.write_text(json.dumps(expired))
    with pytest.raises(RuntimeError, match="expired"):
        store.import_bundle(source)
    assert _kernel_ipv6_route_snapshot() == routes_before, (
        "signed Router-CA bundle import changed the kernel IPv6 route table"
    )


def test_lookup_record_sequence_rollback_is_rejected(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    now = int(time.time())
    newer = _envelope({"router_id": "router-b", "record_seq": 5, "status": "ACTIVE",
                       "valid_until": now + 20, "client_nonce": "n" * 43}, key)
    older = _envelope({"router_id": "router-b", "record_seq": 4, "status": "ACTIVE",
                       "valid_until": now + 20, "client_nonce": "m" * 43}, key)
    _save_verified_cache(settings, lookups={"router-b": newer})
    with pytest.raises(RuntimeError, match="record rollback"):
        _save_verified_cache(settings, lookups={"router-b": older})


def test_ca_unreachable_does_not_fall_back_to_cache(tmp_path, monkeypatch):
    import nls.ca_client as client
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    monkeypatch.setattr(client, "_load_root", lambda _path: object())
    monkeypatch.setattr(client, "_local_certificate", lambda *_args: "test-cert")
    def unavailable(*_args, **_kwargs):
        raise OSError("CA unreachable")
    monkeypatch.setattr(client, "_open_channel", unavailable)
    with pytest.raises(OSError, match="CA unreachable"):
        client.lookup(settings, None, "router-b")



def _kernel_ipv6_route_snapshot():
    if shutil.which("ip") is None:
        pytest.skip("iproute2 is required for kernel route-table snapshot")
    return subprocess.run(
        ["ip", "-6", "route", "show"], check=True, capture_output=True, text=True,
    ).stdout


def test_directory_sync_kernel_route_table_snapshot_no_change(tmp_path, monkeypatch):
    import nls.ca_client as client
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    now = int(time.time())
    initial = _envelope({
        "directory_seq": 1, "expires_at": now + 300, "records": [], "revoked_serials": [],
    }, key)
    update = _envelope({
        "directory_seq": 2, "expires_at": now + 300, "records": [], "revoked_serials": [],
    }, key)
    _save_verified_cache(settings, bundle=initial, lookups={})
    monkeypatch.setattr(client, "_load_root", lambda _path: object())
    monkeypatch.setattr(client, "_local_certificate", lambda *_args: "test-certificate")

    class Channel:
        def send(self, _message):
            pass
        def recv(self):
            return {"type": "directory-sync-result", "ok": True, "directory_bundle": update}
        def close(self):
            pass

    monkeypatch.setattr(client, "_open_channel", lambda *_args: Channel())
    routes_before = _kernel_ipv6_route_snapshot()
    synced = client.directory_sync(settings, None)
    routes_after = _kernel_ipv6_route_snapshot()
    assert synced["directory_seq"] == 2
    assert routes_after == routes_before, (
        "Router-CA directory synchronization changed the kernel IPv6 route table"
    )


def test_offline_mode_disables_live_lookup_and_sync(tmp_path):
    import nls.ca_client as client
    key = ed25519.Ed25519PrivateKey.generate()
    settings = replace(_settings(tmp_path, key), trust_mode="offline")
    with pytest.raises(RuntimeError, match="offline trust mode"):
        client.lookup(settings, None, "router-b")
    with pytest.raises(RuntimeError, match="offline trust mode"):
        client.directory_sync(settings, None)



def test_client_settings_reads_nested_trust_mode_and_stale_grace(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    nls_path = tmp_path / "nls.yaml"
    nls_path.write_text(yaml.safe_dump({"nls": {"trust_mode": "offline", "stale_grace_seconds": 15}}))
    client_path = tmp_path / "router-ca-client.yaml"
    client_path.write_text(yaml.safe_dump({"router_ca": {
        "endpoint": "[::1]:4790",
        "server_public_key": base64.b64encode(public).decode(),
        "router_id": "router-a",
        "nls_config_file": str(nls_path),
    }}))
    loaded = ClientSettings.load(client_path)
    assert loaded.trust_mode == "offline"
    assert loaded.stale_grace_seconds == 15



@pytest.mark.parametrize(("field", "replacement"), [
    ("originalIP", "fd42:100::99"),
    ("certificate_der_b64", base64.b64encode(b"tampered certificate").decode("ascii")),
    ("status", "REVOKED"),
])
def test_signed_rdr_field_tampering_is_rejected(tmp_path, field, replacement):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    envelope = _envelope({
        "router_id": "router-b", "record_seq": 2, "status": "ACTIVE",
        "valid_until": int(time.time()) + 20, "originalIP": "fd42:100::2",
        "certificate_der_b64": base64.b64encode(b"certificate").decode("ascii"),
    }, key)
    tampered = json.loads(json.dumps(envelope))
    tampered["payload"][field] = replacement
    with pytest.raises(RuntimeError, match="signature verification failed"):
        _verify_directory_envelope(tampered, settings)


@pytest.mark.parametrize(("payload_change", "expected_field"), [
    ({"originalIP": None, "original_ip_usable": True, "wan_endpoints": ["[fd42:100::2]:4790"]}, "originalIP"),
    ({"originalIP": "fd42:100::99", "original_ip_usable": True, "wan_endpoints": ["[fd42:100::2]:4790"]}, "originalIP"),
    ({"originalIP": None, "original_ip_usable": False, "wan_endpoints": []}, None),
])
def test_rdr_original_ip_missing_or_mismatched_fails_closed(tmp_path, payload_change, expected_field):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    payload = {
        "router_id": "router-b", "record_seq": 2, "status": "UNKNOWN",
        "valid_until": int(time.time()) + 20, "originalIP": None,
        "original_ip_usable": False, "wan_endpoints": [],
    }
    payload.update(payload_change)
    envelope = _envelope(payload, key)
    if expected_field is None:
        assert _verify_directory_envelope(envelope, settings)["original_ip_usable"] is False
    else:
        with pytest.raises(RuntimeError, match=expected_field):
            _verify_directory_envelope(envelope, settings)


def _make_rdr_certificate(tmp_path, signing_key, router_id="router-b", expired=False):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Router-CA")])
    root_cert = (
        x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key()).serial_number(1)
        .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=365)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    settings = _settings(tmp_path, signing_key)
    settings.ca_certificate_file.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    identity = ed25519.Ed25519PrivateKey.generate()
    before = now - timedelta(days=3) if expired else now - timedelta(minutes=2)
    after = now - timedelta(days=1) if expired else now + timedelta(days=30)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, router_id)]))
        .issuer_name(root_name).public_key(identity.public_key()).serial_number(0x1234)
        .not_valid_before(before.replace(tzinfo=None)).not_valid_after(after.replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    raw = identity.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    spki = identity.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    payload = {
        "rdr_version": 2, "router_id": router_id, "originalIP": "fd42:100::2",
        "original_ip_usable": True, "wan_endpoints": ["[fd42:100::2]:4790"],
        "ed25519_public_key": base64.b64encode(raw).decode("ascii"),
        "ed25519_public_key_spki_der_b64": base64.b64encode(spki).decode("ascii"),
        "rsa_encryption_public_key": None,
        "certificate_der_b64": base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode("ascii"),
        "certificate_serial": "1234", "status": "ACTIVE", "record_seq": 1,
        "issued_at": int(time.time()), "valid_until": int(time.time()) + 20,
    }
    return settings, payload


def test_usable_rdr_rejects_expired_router_certificate(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, payload = _make_rdr_certificate(tmp_path, key, expired=True)
    envelope = _envelope(payload, key)
    with pytest.raises(RuntimeError, match="expired or not yet valid"):
        _verify_directory_envelope(envelope, settings)


def test_usable_rdr_validates_certificate_chain_and_original_ip_binding(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, payload = _make_rdr_certificate(tmp_path, key)
    envelope = _envelope(payload, key)
    assert _verify_directory_envelope(envelope, settings)["originalIP"] == "fd42:100::2"
