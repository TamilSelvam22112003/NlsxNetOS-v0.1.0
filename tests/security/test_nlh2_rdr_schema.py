"""Strict NLH2 Router Directory Record (RDR) schema regressions."""
from __future__ import annotations

import base64
import time

import pytest

from nls.handshake import M2, M3, _v2_schema


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _record() -> dict:
    now = int(time.time())
    return {
        "rdr_version": 2,
        "router_id": "router-r",
        "ed25519_public_key": _b64(b"e" * 32),
        "ed25519_public_key_spki_der_b64": _b64(b"spki"),
        "rsa_encryption_public_key": "rsa-public-key",
        "certificate_der_b64": _b64(b"certificate"),
        "originalIP": "2001:db8::2",
        "original_ip_usable": True,
        "wan_endpoints": ["[2001:db8::2]:4789"],
        "gateway_ips": ["2001:db8::1"],
        "prefixes": ["2001:db8:1::/64"],
        "certificate_serial": "1234",
        "status": "ACTIVE",
        "record_seq": 1,
        "issued_at": now,
        "valid_until": now + 60,
    }


def _message(kind: int, record: dict) -> dict:
    rdr = {
        "payload": record,
        "signer_public_key": _b64(b"s" * 32),
        "signature": _b64(b"x" * 64),
        "encoding": "canonical-cbor",
        "domain": "NLS-DIR-v1",
    }
    common = {"session_id": b"i" * 16, "certificate": b"certificate", "RDR": rdr}
    if kind == M2:
        return {
            **common,
            "router_id": "router-r",
            "gateway_ips": ["2001:db8::1"],
            "sa_proposals": ["NLS-AEAD-v1"],
            "dh_pub_D": b"d" * 32,
            "nonce_d": b"n" * 32,
            "ike_meta": {"version": 1, "nonce_s": b"n" * 32},
            "H1": b"h" * 32,
            "sig_D": b"s" * 64,
        }
    return {
        **common,
        "dh_pub_S": b"d" * 32,
        "chosen_sa": "NLS-AEAD-v1",
        "S.wan_endpoint": "[2001:db8::1]:4789",
        "H2": b"h" * 32,
        "sig_S": b"s" * 64,
    }


@pytest.mark.parametrize("kind", [M2, M3])
def test_rdr_v2_rejects_record_without_explicit_version(kind):
    record = _record()
    del record["rdr_version"]
    with pytest.raises(ValueError, match="NLS_HS_RDR_PAYLOAD_FIELDS"):
        _v2_schema(kind, _message(kind, record))


@pytest.mark.parametrize("kind", [M2, M3])
def test_rdr_v2_rejects_unknown_record_fields(kind):
    record = _record()
    record["unexpected_extension"] = "must-not-be-implicitly-trusted"
    with pytest.raises(ValueError, match="NLS_HS_RDR_PAYLOAD_FIELDS"):
        _v2_schema(kind, _message(kind, record))


@pytest.mark.parametrize("kind", [M2, M3])
def test_rdr_v2_rejects_unusable_original_ip(kind):
    record = _record()
    record["original_ip_usable"] = False
    with pytest.raises(ValueError, match="NLS_HS_RDR_UNUSABLE"):
        _v2_schema(kind, _message(kind, record))


@pytest.mark.parametrize("kind", [M2, M3])
def test_rdr_v2_accepts_exact_versioned_active_record(kind):
    _v2_schema(kind, _message(kind, _record()))
