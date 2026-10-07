import base64
import ipaddress
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from nlsxnetos.nls import handshake
from nlsxnetos.nls.rsa import public_key_b64


def _identity():
    key = ed25519.Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return key, public


def test_vip_mutual_trust_roundtrip_and_promotion():
    source_id, source_public = _identity()
    dest_id, dest_public = _identity()
    source_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    dest_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    source_cert = "CERT-SOURCE"
    dest_cert = "CERT-DEST"
    source_ip = "192.0.2.10"
    dest_ip = "192.0.2.20"

    pending = handshake.new_init(
        "router-a", source_public, source_id, "router-b",
        source_cert, 100, public_key_b64(dest_rsa), source_ip,
    )
    assert len(pending.vip_token) == 128
    assert ipaddress.ip_address(pending.vip_address).version == 6
    assert pending.init_obj["vip_identity_envelope"]

    response, _, _ = handshake.responder_key(
        pending.init_obj, dest_id, dest_public, "router-b", "router-a", source_public,
        dest_cert, 200, dest_rsa, public_key_b64(source_rsa), dest_ip,
    )

    send_key, recv_key = handshake.initiator_key(
        pending, response, dest_public, dest_cert, 200, source_rsa, dest_ip
    )
    assert len(send_key) == 32
    assert len(recv_key) == 32

    confirm = handshake.build_confirm(
        pending, response, source_id, source_ip, source_cert, 100,
        public_key_b64(dest_rsa),
    )
    record = handshake.verify_confirm(
        confirm, source_public, pending.session_id, pending.vip_token,
        source_cert, 100, dest_rsa, source_ip
    )
    assert record["original_ip"] == source_ip
    assert record["trust"] is True


def test_vip_rejects_router_ca_original_ip_mismatch():
    source_id, source_public = _identity()
    dest_id, dest_public = _identity()
    source_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    dest_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    pending = handshake.new_init(
        "router-a", source_public, source_id, "router-b",
        "CERT-SOURCE", 100, public_key_b64(dest_rsa), "192.0.2.10",
    )
    response, _, _ = handshake.responder_key(
        pending.init_obj, dest_id, dest_public, "router-b", "router-a", source_public,
        "CERT-DEST", 200, dest_rsa, public_key_b64(source_rsa), "192.0.2.20",
    )
    try:
        handshake.initiator_key(
            pending, response, dest_public, "CERT-DEST", 200, source_rsa, "192.0.2.99"
        )
    except ValueError as exc:
        assert "original IP" in str(exc)
    else:
        raise AssertionError("vIP trust accepted a Router-CA original-IP mismatch")
