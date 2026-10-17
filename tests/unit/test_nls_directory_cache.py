"""Regression tests for the signed Router Directory Record receive cache."""
import base64
import hashlib
import json
import os
import stat
import time

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
    # On-disk tampering is intentionally observed at the next bounded refresh,
    # not by stat/hash work on each packet.
    ca_client._VERIFIED_RECORD_CACHE[str(settings.directory_file)]["next_check_mono"] = time.monotonic() - 1
    with pytest.raises(RuntimeError, match="content hash mismatch"):
        ca_client.cached_record("router-b", settings)



def test_warm_cache_hot_path_does_not_stat_files_until_refresh(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key)
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"
    entry = ca_client._VERIFIED_RECORD_CACHE[str(settings.directory_file)]
    entry["next_check_mono"] = time.monotonic() + 30

    def unexpected_stat(_settings):
        raise AssertionError("warm-cache packet path performed filesystem stat")

    monkeypatch.setattr(ca_client, "_cache_file_signatures", unexpected_stat)
    assert ca_client.cached_record("router-b", settings)["record_seq"] == 7


def test_missing_or_lower_rollback_mark_fails_closed(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, bundle_payload, _ = _settings(tmp_path, key)
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"
    settings.rollback_mark_file.unlink()
    with pytest.raises(RuntimeError, match="rollback mark missing"):
        ca_client.cached_record("router-b", settings)

    # A fresh live bundle can repair a missing mark, but a mark below the cache
    # sequence is not accepted as trusted state.
    settings.rollback_mark_file.write_text(json.dumps({
        "version": 1, "directory_seq": 0, "record_seq": {"router-b": 7},
        "bundle_valid_until": bundle_payload["expires_at"],
        "cache_sha256": hashlib.sha256(settings.directory_file.read_bytes()).hexdigest(),
        "updated_at": int(time.time()),
    }), encoding="utf-8")
    settings.rollback_mark_file.chmod(0o600)
    with pytest.raises(RuntimeError, match="sequence does not match"):
        ca_client.cached_record("router-b", settings)
    # A fresh, higher-sequence CA-signed bundle can repair a lower/mismatched mark.
    fresh_payload = dict(bundle_payload)
    fresh_payload["directory_seq"] = bundle_payload["directory_seq"] + 1
    fresh_payload["issued_at"] = int(time.time())
    fresh_payload["expires_at"] = int(time.time()) + 120
    fresh_envelope = _sign(fresh_payload, key)
    ca_client._save_verified_cache(
        settings, bundle=fresh_envelope, lookups={}, allow_mark_repair=True,
    )
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"


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


def test_directory_sequence_and_revocation_invalidate_warm_record_cache(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, bundle_payload, bundle_envelope = _settings(tmp_path, key)
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"
    cache_entry = ca_client._VERIFIED_RECORD_CACHE[str(settings.directory_file)]
    assert cache_entry["next_check_mono"] - time.monotonic() <= 5.1

    # Force the next access to perform the bounded refresh after the CA state
    # changes; the warm-cache packet path itself does not stat the filesystem.
    ca_client._VERIFIED_RECORD_CACHE[str(settings.directory_file)]["next_check_mono"] = time.monotonic() - 1
    old_record_envelope = bundle_envelope["payload"]["records"][0]
    revoked_record = dict(old_record_envelope["payload"])
    revoked_record["record_seq"] = 8
    revoked_record["status"] = "REVOKED"
    revoked_record["issued_at"] = int(time.time())
    revoked_record["valid_until"] = int(time.time()) + 60
    revoked_envelope = _sign(revoked_record, key)
    updated_bundle = dict(bundle_payload)
    updated_bundle["directory_seq"] = 10
    updated_bundle["issued_at"] = int(time.time())
    updated_bundle["expires_at"] = int(time.time()) + 120
    updated_bundle["records"] = [revoked_envelope]
    updated_bundle["revoked_serials"] = ["abc123"]
    new_envelope = _sign(updated_bundle, key)
    ca_client._save_verified_cache(
        settings, bundle=new_envelope, lookups={}, allow_mark_repair=True
    )
    with pytest.raises(RuntimeError, match="not active|revoked"):
        ca_client.cached_record("router-b", settings)
