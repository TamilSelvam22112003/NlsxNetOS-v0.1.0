"""Regression tests for the signed Router Directory Record receive cache."""
import base64
import hashlib
import json
import os
import stat
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
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
    now_dt = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key()).serial_number(0x1000)
        .not_valid_before((now_dt - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((now_dt + timedelta(days=365)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "router-b")]))
        .issuer_name(root_name)
        .public_key(ed_key.public_key())
        .serial_number(0xabc123)
        .not_valid_before((now_dt - timedelta(minutes=1)).replace(tzinfo=None))
        .not_valid_after((now_dt + timedelta(days=1)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    raw_key = ed_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    spki_der = ed_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    certificate_der_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    record = {
        "rdr_version": 2,
        "router_id": "router-b",
        "ed25519_public_key": base64.b64encode(raw_key).decode("ascii"),
        "ed25519_public_key_spki_der_b64": base64.b64encode(spki_der).decode("ascii"),
        "rsa_encryption_public_key": rsa_pem,
        "certificate_der_b64": certificate_der_b64,
        "originalIP": "fd00::2",
        "original_ip_usable": True,
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
    (tmp_path / "ca-root.crt").write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
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



def test_verified_cache_loader_retries_atomic_publication_race(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key)
    original_validate = ca_client._validate_rollback_mark
    calls = {"count": 0}

    def validate_with_one_publication_race(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("Router-CA cache state changed during verification; retry lookup")
        return original_validate(*args, **kwargs)

    monkeypatch.setattr(ca_client, "_validate_rollback_mark", validate_with_one_publication_race)
    cache, payload = ca_client._load_verified_cache(settings)
    assert payload["directory_seq"] == 9
    assert cache["bundle"]["payload"]["directory_seq"] == 9
    assert calls["count"] == 2


def test_verified_cache_loader_retries_transient_cache_mark_mismatch(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key)
    original_validate = ca_client._validate_rollback_mark
    calls = {"count": 0}

    def validate_with_publication_window(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError(
                "Router-CA directory cache content hash mismatch; fresh live sync required"
            )
        return original_validate(*args, **kwargs)

    monkeypatch.setattr(ca_client, "_validate_rollback_mark", validate_with_publication_window)
    cache, payload = ca_client._load_verified_cache(settings)
    assert payload["directory_seq"] == 9
    assert cache["bundle"]["payload"]["directory_seq"] == 9
    assert calls["count"] == 2


def test_verified_cache_loader_fails_closed_on_persistent_hash_mismatch(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key)
    calls = {"count": 0}

    def persistent_mismatch(*args, **kwargs):
        calls["count"] += 1
        raise RuntimeError(
            "Router-CA directory cache content hash mismatch; fresh live sync required"
        )

    monkeypatch.setattr(ca_client, "_validate_rollback_mark", persistent_mismatch)
    with pytest.raises(RuntimeError, match="content hash mismatch"):
        ca_client._load_verified_cache(settings)
    assert calls["count"] == 8


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
    # Rollback-mark integrity is rechecked at the next bounded refresh.
    ca_client._VERIFIED_RECORD_CACHE[str(settings.directory_file)]["next_check_mono"] = time.monotonic() - 1
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


def test_cached_record_expires_when_record_valid_until_expires(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key, expiry_offset=120)
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"
    entry = ca_client._VERIFIED_RECORD_CACHE[str(settings.directory_file)]
    entry["next_check_mono"] = time.monotonic() + 30
    original_now = int(time.time())
    # The directory bundle remains fresh, but the individual RDR expires.
    monkeypatch.setattr(ca_client.time, "time", lambda: original_now + 61)
    with pytest.raises(RuntimeError, match="record is stale"):
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



def test_cache_writer_lock_serializes_cache_and_rollback_mark_publication(tmp_path, monkeypatch):
    import threading

    key = ed25519.Ed25519PrivateKey.generate()
    settings, payload, envelope = _settings(tmp_path, key)
    newer_payload = dict(payload)
    newer_payload["directory_seq"] += 1
    newer_payload["issued_at"] = int(time.time())
    newer_payload["expires_at"] = int(time.time()) + 120
    newer_envelope = _sign(newer_payload, key)
    original = ca_client._save_verified_cache_locked
    entered = threading.Event()
    release = threading.Event()
    writes = []

    def paused_writer(settings_arg, bundle=None, lookups=None, allow_mark_repair=False):
        if bundle == envelope:
            entered.set()
            assert release.wait(timeout=2)
        writes.append(bundle)
        return original(settings_arg, bundle=bundle, lookups=lookups, allow_mark_repair=allow_mark_repair)

    monkeypatch.setattr(ca_client, "_save_verified_cache_locked", paused_writer)
    first = threading.Thread(target=ca_client._save_verified_cache, kwargs={"settings": settings, "bundle": envelope, "lookups": {}, "allow_mark_repair": True})
    second = threading.Thread(target=ca_client._save_verified_cache, kwargs={"settings": settings, "bundle": newer_envelope, "lookups": {}, "allow_mark_repair": True})
    first.start()
    assert entered.wait(timeout=2)
    second.start()
    release.set()
    first.join(timeout=3)
    second.join(timeout=3)
    assert not first.is_alive() and not second.is_alive()
    cache, verified = ca_client._load_verified_cache(settings)
    assert verified["directory_seq"] == newer_payload["directory_seq"]
    mark, error = ca_client._read_rollback_mark(settings)
    assert error is None
    assert mark["directory_seq"] == newer_payload["directory_seq"]
    assert mark["cache_sha256"] == hashlib.sha256(settings.directory_file.read_bytes()).hexdigest()


def test_empty_cache_does_not_retain_stale_bundle_expiry_in_rollback_mark(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings, _, _ = _settings(tmp_path, key)
    empty_cache = {"bundle": None, "lookups": {}}
    cache_bytes = json.dumps(empty_cache, sort_keys=True, separators=(",", ":")).encode()
    settings.directory_file.write_bytes(cache_bytes)
    settings.rollback_mark_file.write_text(json.dumps({
        "version": 1,
        "directory_seq": 0,
        "record_seq": {},
        "bundle_valid_until": int(time.time()) + 300,
        "cache_sha256": hashlib.sha256(cache_bytes).hexdigest(),
        "updated_at": int(time.time()),
    }), encoding="utf-8")
    settings.rollback_mark_file.chmod(0o600)

    ca_client._save_verified_cache(settings, bundle=None, lookups={})
    mark = json.loads(settings.rollback_mark_file.read_text(encoding="utf-8"))
    assert mark["bundle_valid_until"] == 0
    cache, payload = ca_client._load_verified_cache(settings)
    assert cache["bundle"] is None
    assert payload is None

def test_stale_record_reader_cannot_republish_after_concurrent_cache_update(tmp_path, monkeypatch):
    """A cache reader racing a newer signed RDR must not republish its stale snapshot."""
    import threading

    key = ed25519.Ed25519PrivateKey.generate()
    settings, payload, envelope = _settings(tmp_path, key)
    ca_client._VERIFIED_RECORD_CACHE.pop(str(settings.directory_file), None)

    reader_at_final_check = threading.Event()
    writer_finished = threading.Event()
    original_signatures = ca_client._cache_file_signatures
    calls = 0
    result = {}

    def pause_reader_before_publish(settings_arg):
        nonlocal calls
        signatures = original_signatures(settings_arg)
        calls += 1
        # Calls 1 and 2 bracket the initial snapshot; call 3 is the pre-publish
        # consistency check. Pause after taking that snapshot so a writer can
        # update the cache in the exact window that previously allowed stale
        # in-memory state to be republished after invalidation.
        if calls == 3:
            reader_at_final_check.set()
            assert writer_finished.wait(timeout=3)
        return signatures

    monkeypatch.setattr(ca_client, "_cache_file_signatures", pause_reader_before_publish)

    def read_record():
        try:
            result["record"] = ca_client._cached_record_once("router-b", settings)
        except Exception as exc:
            result["error"] = exc

    reader = threading.Thread(target=read_record)
    reader.start()
    assert reader_at_final_check.wait(timeout=3)

    old_record = envelope["payload"]["records"][0]["payload"]
    revoked_record = dict(old_record)
    revoked_record["record_seq"] = int(old_record["record_seq"]) + 1
    revoked_record["status"] = "REVOKED"
    revoked_record["issued_at"] = int(time.time())
    revoked_record["valid_until"] = int(time.time()) + 120
    revoked_envelope = _sign(revoked_record, key)
    newer_payload = dict(payload)
    newer_payload["directory_seq"] = int(payload["directory_seq"]) + 1
    newer_payload["issued_at"] = int(time.time())
    newer_payload["expires_at"] = int(time.time()) + 120
    newer_payload["records"] = [revoked_envelope]
    newer_envelope = _sign(newer_payload, key)
    try:
        ca_client._save_verified_cache(
            settings, bundle=newer_envelope, lookups={}, allow_mark_repair=True
        )
    finally:
        writer_finished.set()
    reader.join(timeout=4)

    assert not reader.is_alive()
    assert "record" not in result
    assert isinstance(result.get("error"), RuntimeError)
    assert "cache state changed during verification" in str(result["error"])
    with pytest.raises(RuntimeError, match="not active|revoked"):
        ca_client.cached_record("router-b", settings)

def test_invalidate_verified_record_cache_refreshes_external_agent_update(tmp_path):
    """A daemon can discard stale memory after the separate CA agent updates disk."""
    key = ed25519.Ed25519PrivateKey.generate()
    settings, payload, envelope = _settings(tmp_path, key)
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"
    cache_key = str(settings.directory_file)
    stale_entry = ca_client._VERIFIED_RECORD_CACHE[cache_key]

    old_record = envelope["payload"]["records"][0]["payload"]
    revoked_record = dict(old_record)
    revoked_record["record_seq"] = int(old_record["record_seq"]) + 1
    revoked_record["status"] = "REVOKED"
    revoked_record["issued_at"] = int(time.time())
    revoked_record["valid_until"] = int(time.time()) + 120
    revoked_envelope = _sign(revoked_record, key)
    newer_payload = dict(payload)
    newer_payload["directory_seq"] = int(payload["directory_seq"]) + 1
    newer_payload["issued_at"] = int(time.time())
    newer_payload["expires_at"] = int(time.time()) + 120
    newer_payload["records"] = [revoked_envelope]
    newer_envelope = _sign(newer_payload, key)
    ca_client._save_verified_cache(
        settings, bundle=newer_envelope, lookups={}, allow_mark_repair=True
    )

    # Simulate another process: its write cannot clear this process's Python dict.
    with ca_client._VERIFIED_RECORD_CACHE_LOCK:
        ca_client._VERIFIED_RECORD_CACHE[cache_key] = stale_entry
    assert ca_client.cached_record("router-b", settings)["status"] == "ACTIVE"

    ca_client.invalidate_verified_record_cache(settings)
    with pytest.raises(RuntimeError, match="not active|revoked"):
        ca_client.cached_record("router-b", settings)

