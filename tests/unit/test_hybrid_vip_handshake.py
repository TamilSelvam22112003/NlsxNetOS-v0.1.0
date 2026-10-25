"""Regression tests for the hybrid minimal-disclosure NLH2 M1 schema."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from nls.handshake import M1, _v2_schema, sign_v2, verify_v2_signature


def _m1():
    return {
        "session_id": b"s" * 16,
        "source_router_id": "router-s",
        "source_ed25519_pub": b"e" * 32,
        "source_rsa_pub": b"rsa-spki-test",
        "request_for_peer_details": True,
        "destination_router_id": "router-d",
        "vip": "3191:9059:1edf:8053:5a34:18d1:8480:636d",
        "vip_nonce": b"v" * 32,
        "time_bucket": 58_000_000,
        "vip_policy_version": 1,
        "nonce_s": b"n" * 32,
        "timestamp": 1_800_000_000,
        "padding": b"p" * 7600,
    }


def test_hybrid_m1_exact_schema_is_accepted():
    _v2_schema(M1, {**_m1(), "sig_S": b"x" * 64})


def test_legacy_m1_schema_is_rejected():
    legacy = {
        "session_id": b"s" * 16,
        "router_id": "router-s",
        "ed25519_public_key": b"e" * 32,
        "rsa_encryption_public_key": b"rsa-spki-test",
        "nonce_s": b"n" * 32,
        "timestamp": 1_800_000_000,
        "vip": "fd00::1",
        "padding": b"p" * 7600,
        "sig_S": b"x" * 64,
    }
    with pytest.raises(ValueError, match="NLS_HS_SCHEMA_FIELDS"):
        _v2_schema(M1, legacy)


def test_hybrid_m1_rejects_unknown_fields():
    with pytest.raises(ValueError, match="NLS_HS_SCHEMA_FIELDS"):
        _v2_schema(M1, {**_m1(), "legacy_original_ip": "2001:4860::1", "sig_S": b"x" * 64})


@pytest.mark.parametrize("changes, error", [
    ({"request_for_peer_details": False}, "NLS_HS_PEER_DETAILS_REQUEST"),
    ({"vip_nonce": b"short"}, "NLS_HS_NONCE_LENGTH"),
    ({"nonce_s": b"short"}, "NLS_HS_NONCE_LENGTH"),
    ({"time_bucket": True}, "NLS_HS_SCHEMA_TYPE"),
    ({"time_bucket": -1}, "NLS_HS_TIME_BUCKET"),
    ({"time_bucket": 1 << 64}, "NLS_HS_TIME_BUCKET"),
    ({"vip_policy_version": 2}, "NLS_HS_VIP_POLICY_VERSION"),
])
def test_hybrid_m1_rejects_invalid_security_fields(changes, error):
    with pytest.raises(ValueError, match=error):
        _v2_schema(M1, {**_m1(), **changes, "sig_S": b"x" * 64})


def test_hybrid_m1_signature_covers_vip_nonce_and_policy_fields():
    private_key = ed25519.Ed25519PrivateKey.generate()
    signed = sign_v2(M1, _m1(), private_key)
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    verify_v2_signature(M1, signed, public_raw)
    tampered = dict(signed)
    tampered["vip_nonce"] = b"z" * 32
    with pytest.raises(ValueError, match="NLS_HS_SIGNATURE_INVALID"):
        verify_v2_signature(M1, tampered, public_raw)
