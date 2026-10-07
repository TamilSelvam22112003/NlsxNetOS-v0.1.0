import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import base64
from pathlib import Path

import pytest

from nlsxnetos.router_ca.models import RouterCAEntry
from nlsxnetos.router_ca import store
from nlsxnetos.nls import handshake\nfrom cryptography.hazmat.primitives.asymmetric import rsa\nfrom nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64


def _key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode()


def test_router_ca_rejects_duplicate_active_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "PATH", tmp_path / "router-ca.yaml")
    key = _key(7)
    store.save([
        RouterCAEntry(1, "2001:db8:1::/64", "a", key, "[2001:db8::1]:4789"),
    ])
    with pytest.raises(ValueError, match="duplicate active Router-CA public key"):
        store.save([
            RouterCAEntry(1, "2001:db8:1::/64", "a", key, "[2001:db8::1]:4789"),
            RouterCAEntry(2, "2001:db8:2::/64", "b", key, "[2001:db8::2]:4789"),
        ])


def test_handshake_rejects_stale_response(monkeypatch):
    import time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from nlsxnetos.nls.identity import public_key_b64

    private = Ed25519PrivateKey.generate()
    public = public_key_b64(private)
    pending = handshake.new_init("router-a", public, private, "router-b")
    response = {
        "router_id": "router-b",
        "peer_id": "router-a",
        "identity_public_key": public,
        "ephemeral_public_key": pending.init_obj["ephemeral_public_key"],
        "session_id": pending.session_id.hex(),
        "timestamp": 0,
        "protocol_version": 1,
        "init_digest": __import__("hashlib").sha256(
            handshake.canonical(pending.init_obj)
        ).hexdigest(),
    }
    signed = handshake.sign(response, handshake.RESPONSE, private)
    monkeypatch.setattr(
        handshake,
        "_timestamp_ok",
        lambda value: (_ for _ in ()).throw(ValueError("timestamp")),
    )
    with pytest.raises(ValueError, match="timestamp"):
        handshake.initiator_key(pending, signed, public)


def test_nls_service_is_not_root():
    text = Path("systemd/nls-router.service").read_text(encoding="utf-8")
    assert "User=nlsxnetos" in text
    assert "Group=nlsxnetos" in text
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in text
    assert "NoNewPrivileges=true" in text
    assert "DeviceAllow=/dev/net/tun rw" in text
