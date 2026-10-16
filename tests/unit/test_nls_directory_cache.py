"""Regression tests for the signed Router Directory Record receive cache."""
import base64
import hashlib
import json
import os
import stat
import time
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from nls import ca_client


def _sign(payload, key):
    return {
        "payload": payload,
        "signer_public_key": base64.b64encode(
            key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii"),
        "signature": base64.b64encode(key.sign(
            b"NLS-DIR-v1" + cbor2.dumps(payload, canonical=True)
        )).decode("ascii"),
        "encoding": "canonical-cbor",
        "domain": "NLS-DIR-v1",
    }


def _settings(tmp_path, key, *, expiry_offset=120):
    now = int(time.time())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    ed_key = ed25519.Ed25519PrivateKey.generate()
    record = {
        "router_id": "router-b",
        "ed25519_public_key": base64.b64encode(
            ed_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii"),
        "rsa_encryption_public_key": rsa_pem,
        "wan_endpoints": ["[fd00::2]:4789"],
        "gateway_ips": ["10.2.0.1"],
        "prefixes": ["10.2.0.0/24"],
        "certificate_serial": "abc123",
        "status": "ACTIVE",
        "record_seq": 7,
        "issued_at": now,
        "valid_until": now + 60,
    }
    record_envelope = _sign(record, key)
    bundle_payload = {
        "bundle_version": 1,
        "directory_seq": 9,
        "issued_at": now,
        "expires_at": now + expiry_offset,
        "records": [record_envelope],
        "revoked_serials": [],
        "policy": {"replay_window": 128},
    }
    bundle = _sign(bundle_payload, key)
    cache_dir = tmp_path / "cache"
    state_dir = tmp_path / "state"
    cache_dir.mkdir()
    state_dir.mkdir()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    settings = ca_client.ClientSettings(
        endpoint="[::1]:4790",
        server_id="test-ca",
        server_public_key=base64.b64encode(public).decode("ascii"),
        router_id="router-a",
        identity_key=tmp_path / "identity.key",
        certificate_file=tmp_path / "router.crt",
        ca_certificate_file=tmp_path / "ca-root.crt",
        bootstrap_token_file=tmp_path / "bootstrap.token",
        router_token_file=tmp_path / "router.token",
        policy_file=state_dir / "policy.json",
        revocation_file=state_dir / "revocations.json",
        directory_file=cache_dir / "router-directory.json",
        rollback_mark_file=state_dir / "directory-rollback-mark.json",
    )
    ca_client._save_verified_cache(settings, bundle=bundle, lookups={}, allow_mark_repair=True)
    return settings, bundle_payload, bundle


def test_warm_cache_rejects_content_tampering(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key)
    assert ca_client.cached_record("router-b", settings)["record_seq"] == 7
    # Warm the in-memory cache, then change the on-disk cache without updating its mark.
    original = settings.directory_file.read_bytes()
    settings.directory_file.write_bytes(original + b" ")
    with pytest.raises(RuntimeError, match="content hash mismatch"):
        ca_client.cached_record("router-b", settings)


def test_missing_or_lower_rollback_mark_fails_closed(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key)
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"
    settings.rollback_mark_file.unlink()
    with pytest.raises(RuntimeError, match="rollback mark missing"):
        ca_client.cached_record("router-b", settings)

    # A fresh live bundle can repair a missing mark, but a mark below the cache
    # sequence is not accepted as trusted state.
    settings.rollback_mark_file.write_text(json.dumps({
        "version": 1, "directory_seq": 0, "record_seq": {"router-b": 7},
        "bundle_valid_until": int(time.time()) + 120,
        "cache_sha256": hashlib.sha256(settings.directory_file.read_bytes()).hexdigest(),
        "updated_at": int(time.time()),
    }), encoding="utf-8")
    with pytest.raises(RuntimeError, match="sequence does not match"):
        ca_client.cached_record("router-b", settings)


def test_cached_record_expires_when_bundle_freshness_expires(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key, expiry_offset=30)
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"
    original_now = int(time.time())
    monkeypatch.setattr(ca_client.time, "time", lambda: original_now + 31)
    with pytest.raises(RuntimeError, match="freshness expired"):
        ca_client.cached_record("router-b", settings)


def test_rollback_mark_is_outside_cache_and_mode_0600(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key)
    mark = settings.rollback_mark_file
    assert mark.parent != settings.directory_file.parent
    assert stat.S_IMODE(mark.stat().st_mode) == 0o600
    if os.name == "posix":
        import pwd
        try:
            service_uid = pwd.getpwnam("nlsxnetos").pw_uid
        except KeyError:
            service_uid = None
        if service_uid is not None:
            assert mark.stat().st_uid == service_uid
