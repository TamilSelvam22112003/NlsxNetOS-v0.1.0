import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import base64
import json
import time
import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from security.trust.router_ca.models import RouterCAEntry
from security.trust.router_ca import store
from nls import handshake
from nls.identity import public_key_b64


def _key(seed: int) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode()


def _rsa_public_b64() -> str:
    private = generate_private_key(public_exponent=65537, key_size=2048)
    raw = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(raw).decode()


def _signed(payload, ca_key):
    raw = ca_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "payload": payload,
        "signer_public_key": base64.b64encode(raw).decode(),
        "signature": base64.b64encode(ca_key.sign(b"NLS-DIR-v1" + cbor2.dumps(payload, canonical=True))).decode(),
        "encoding": "canonical-cbor",
        "domain": "NLS-DIR-v1",
    }


def test_router_ca_rejects_duplicate_active_identity(tmp_path, monkeypatch):
    key = _key(7)
    encryption_key = _rsa_public_b64()
    ed_public = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32).public_key()
    ed_pem = ed_public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    rsa_pem = serialization.load_der_public_key(base64.b64decode(encryption_key)).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    ca_key = Ed25519PrivateKey.generate()
    pinned = ca_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    config = tmp_path / "router-ca-client.yaml"
    config.write_text("router_ca:\n  server_public_key: '" + base64.b64encode(pinned).decode() + "'\n")
    monkeypatch.setattr(store, "CLIENT_CONFIG", config)
    cache_path = tmp_path / "router-directory.json"
    monkeypatch.setattr(store, "CACHE_PATH", cache_path)
    now = int(time.time())
    records = []
    for router_id, prefix, endpoint in [
        ("router-a", "2001:db8:1::/64", "[2001:db8::1]:4789"),
        ("router-b", "2001:db8:2::/64", "[2001:db8::2]:4789"),
    ]:
        record = {
            "router_id": router_id, "ed25519_public_key": ed_pem,
            "rsa_encryption_public_key": rsa_pem, "wan_endpoints": [endpoint],
            "gateway_ips": [], "prefixes": [prefix], "certificate_serial": router_id + "-serial",
            "status": "ACTIVE", "record_seq": 1, "issued_at": now, "valid_until": now + 300,
        }
        records.append(_signed(record, ca_key))
    bundle = _signed({"directory_seq": 2, "issued_at": now, "expires_at": now + 300,
                      "records": records, "revoked_serials": [], "policy": {}}, ca_key)
    cache_path.write_text(json.dumps({"bundle": bundle, "lookups": {}}))
    with pytest.raises(RuntimeError, match="duplicate active Router-CA public key"):
        store.load()


def test_handshake_rejects_stale_response(monkeypatch):
    private = Ed25519PrivateKey.generate()
    public = public_key_b64(private)
    pending = handshake.new_init(
        "router-a",
        public,
        private,
        "router-b",
        "2001:db8:10::1",
        10,
        public,
        "[2001:db8::2]:4789",
    )
    response = {
        "router_id": "router-b",
        "peer_id": "router-a",
        "identity_public_key": public,
        "ephemeral_public_key": pending.init_obj["ephemeral_public_key"],
        "session_id": pending.session_id.hex(),
        "timestamp": 0,
        "protocol_version": 1,
        "vip": pending.init_obj["vip"],
        "original_ip": pending.init_obj["original_ip"],
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
    text = Path("config/systemd/nls-router.service").read_text(encoding="utf-8")
    assert "User=nlsxnetos" in text
    assert "Group=nlsxnetos" in text
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in text
    assert "NoNewPrivileges=true" in text
    assert "DeviceAllow=/dev/net/tun rw" in text


def test_nls_tunnel_does_not_attempt_ca_lookup_for_ipv6_multicast():
    import ipaddress

    destination = "ff02::2"
    assert ipaddress.ip_address(destination).is_multicast
