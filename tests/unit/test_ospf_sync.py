import base64
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nls import ca_client, lsdb, ospf_sync
from nls.ospf_opaque import decode_record


def _keypair():
    private = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    public = base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode("ascii")
    return private, public


def _record(public_key, **overrides):
    record = {
        "record_version": 1,
        "record_type": "nls_vip_binding",
        "vip": "2001:db8:400::1",
        "original_ip": "2001:db8:400::10",
        "router_id": "router-a",
        "identity_public_key": public_key,
        "source_token": "2001:db8:400::1",
        "send_token": "2001:db8:400::2",
        "local_original_ip": "2001:db8:400::20",
        "session_id": "session-a",
        "record_seq": 7,
        "state": "ESTABLISHED",
        "expires_at": time.time() + 120,
    }
    record.update(overrides)
    return record


def test_encode_registry_snapshot_preserves_canonical_registry_fields():
    private, public = _keypair()
    record = _record(public)
    encoded = ospf_sync.encode_registry_snapshot(
        [record], ospf_router_id="192.0.2.10", sign=private.sign
    )
    assert len(encoded) == 1
    opaque_id, payload = encoded[0]
    assert 1 <= opaque_id <= 0xFFFFFF

    def verify(router_id, identity_public_key, data, signature):
        if router_id != "router-a" or identity_public_key != public:
            return False
        try:
            private.public_key().verify(signature, data)
            return True
        except Exception:
            return False

    decoded = decode_record(payload, verify, advertising_router="192.0.2.10")
    assert decoded["router_id"] == "router-a"
    assert decoded["ospf_router_id"] == "192.0.2.10"
    assert decoded["send_token"] == "2001:db8:400::2"
    assert decoded["local_original_ip"] == "2001:db8:400::20"


def test_registry_snapshot_fails_closed_on_opaque_id_collision(monkeypatch):
    _, public = _keypair()
    records = [
        _record(public, vip="2001:db8:401::1"),
        _record(public, vip="2001:db8:402::1"),
    ]
    monkeypatch.setattr(ospf_sync, "opaque_id_for_record", lambda record: 42)
    with pytest.raises(ValueError, match="opaque-ID collision"):
        ospf_sync.encode_registry_snapshot(
            records, ospf_router_id="192.0.2.10", sign=lambda data: b"x" * 64
        )


def test_router_ca_verifier_requires_active_fresh_matching_identity(monkeypatch):
    private, public = _keypair()
    settings = SimpleNamespace(trust_mode="ca")
    monkeypatch.setattr(ca_client, "directory_freshness", lambda settings: 120)
    monkeypatch.setattr(ca_client, "heartbeat_freshness", lambda settings: 120)
    monkeypatch.setattr(
        ca_client,
        "cached_record",
        lambda router_id, settings: {
            "router_id": "router-a",
            "status": "ACTIVE",
            "valid_until": int(time.time()) + 120,
            "ed25519_public_key": public,
            "certificate_serial": "serial-a",
        },
    )
    monkeypatch.setattr(ca_client, "is_revoked", lambda serial, settings: False)
    verify = ospf_sync.router_ca_verifier(settings)
    message = b"NLS OSPF registry test"
    signature = private.sign(message)
    assert verify("router-a", public, message, signature) is True
    assert verify("router-a", "A" * 44, message, signature) is False
    monkeypatch.setattr(ca_client, "is_revoked", lambda serial, settings: True)
    assert verify("router-a", public, message, signature) is False


def test_verified_routing_withdrawal_is_session_scoped_and_persistent(tmp_path, monkeypatch):
    _, public = _keypair()
    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    monkeypatch.setattr(lsdb, "ROUTING_SEQUENCE_PATH", tmp_path / "routing-sequences.json")
    record = _record(public)
    record["expires_at"] = time.time() + 120
    ospf_record = dict(record, ospf_router_id="192.0.2.10")
    assert ospf_sync.accept_verified_record(
        ospf_record, authenticated_router_id="router-a"
    )["session_id"] == "session-a"
    assert lsdb.get(record["vip"]) is not None

    withdrawal = dict(ospf_record, state="WITHDRAWN", record_seq=8)
    assert ospf_sync.accept_verified_record(
        withdrawal, authenticated_router_id="router-a"
    ) is True
    assert lsdb.get(record["vip"]) is None

    with pytest.raises(ValueError, match="stale NLS routing record sequence"):
        ospf_sync.accept_verified_record(
            ospf_record, authenticated_router_id="router-a"
        )
