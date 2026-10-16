import base64
import json
import time

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nls.ca_client import (
    ClientSettings, _DIRECTORY_DOMAIN, _load_verified_cache, _save_verified_cache,
    _verify_directory_envelope, directory_freshness, is_revoked,
)


def _envelope(payload, key):
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


def test_expired_cache_fails_closed_for_revocation_state(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    settings = _settings(tmp_path, key)
    expired = _envelope({"directory_seq": 1, "expires_at": int(time.time()) - 1,
                         "records": [], "revoked_serials": ["a1"]}, key)
    _save_verified_cache(settings, bundle=expired, lookups={})
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
