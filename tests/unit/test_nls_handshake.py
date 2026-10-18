import os
import base64
from datetime import datetime, timedelta

import cbor2
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from nls.handshake import (
    M2, M3, M4, V2_MAGIC, decode_v2_envelope, encode_v2_message, open_v2_message,
    sign_v2, verify_v2_signature, transcript_h1, transcript_h2, transcript_h3,
)
from nls.seal import SealError


def _m4(sid, key):
    return sign_v2(M4, {
        "session_id": sid, "trust": True, "H3": os.urandom(32),
        "confirm": os.urandom(32), "sig_D": b"",
    }, key)


def test_nlh2_sealed_message_round_trip_and_signature_verification():
    sid = os.urandom(16)
    signer = ed25519.Ed25519PrivateKey.generate()
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    obj = _m4(sid, signer)
    packet = encode_v2_message(
        M4, sid, recipient.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ), obj,
    )
    assert packet.startswith(V2_MAGIC)
    kind, parsed_sid, _envelope, _aad = decode_v2_envelope(packet)
    assert (kind, parsed_sid) == (M4, sid)
    decoded_kind, decoded_sid, decoded, plaintext = open_v2_message(packet, recipient)
    assert (decoded_kind, decoded_sid) == (M4, sid)
    assert decoded == obj
    verify_v2_signature(M4, decoded, signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ))
    assert transcript_h1(plaintext) == transcript_h1(plaintext)
    assert transcript_h2(plaintext, plaintext) != transcript_h1(plaintext)
    assert transcript_h3(plaintext, plaintext, plaintext) != transcript_h2(plaintext, plaintext)


def test_nlh2_rejects_wrong_recipient_key_and_header_tampering():
    sid = os.urandom(16)
    signer = ed25519.Ed25519PrivateKey.generate()
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    obj = _m4(sid, signer)
    packet = encode_v2_message(
        M4, sid, recipient.public_key(), obj
    )
    other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with pytest.raises(ValueError):
        open_v2_message(packet, other)
    tampered = bytearray(packet)
    tampered[5] = 3
    # Type 3 is syntactically valid, so changed AAD must fail authentication.
    with pytest.raises(ValueError):
        open_v2_message(bytes(tampered), recipient)
    invalid_header = bytearray(packet)
    invalid_header[4] = 2
    with pytest.raises(ValueError):
        decode_v2_envelope(bytes(invalid_header))


def test_nlh2_signature_rejects_mutated_transcript_field():
    sid = os.urandom(16)
    signer = ed25519.Ed25519PrivateKey.generate()
    obj = _m4(sid, signer)
    public = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    verify_v2_signature(M4, obj, public)
    obj["H3"] = os.urandom(32)
    with pytest.raises(ValueError, match="NLS_HS_SIGNATURE_INVALID"):
        verify_v2_signature(M4, obj, public)


def test_nlh2_schema_rejects_unknown_and_missing_fields():
    sid = os.urandom(16)
    signer = ed25519.Ed25519PrivateKey.generate()
    obj = _m4(sid, signer)
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with pytest.raises(ValueError, match="NLS_HS_SCHEMA_FIELDS"):
        encode_v2_message(M4, sid, recipient.public_key(), {**obj, "extension": 1})
    with pytest.raises(ValueError, match="NLS_HS_SCHEMA_FIELDS"):
        encode_v2_message(M4, sid, recipient.public_key(), {k: v for k, v in obj.items() if k != "trust"})


def _rdr_v2(router_key, ca_key, rsa_key, router_id="router-v2"):
    now = datetime.utcnow()
    serial_number = 0x123456
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, router_id)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(router_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(router_key, algorithm=None)
    )
    raw_key = router_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    spki_der = router_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    rsa_pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    endpoint = "[fd42:100::2]:4789"
    payload = {
        "rdr_version": 2,
        "router_id": router_id,
        "ed25519_public_key": base64.b64encode(raw_key).decode("ascii"),
        "ed25519_public_key_spki_der_b64": base64.b64encode(spki_der).decode("ascii"),
        "rsa_encryption_public_key": rsa_pem,
        "certificate_der_b64": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii"),
        "originalIP": "fd42:100::2",
        "original_ip_usable": True,
        "wan_endpoints": [endpoint],
        "gateway_ips": [],
        "prefixes": ["fd42:100::/64"],
        "certificate_serial": format(serial_number, "x"),
        "status": "ACTIVE",
        "record_seq": 1,
        "issued_at": int(now.timestamp()),
        "valid_until": int(now.timestamp()) + 30,
    }
    ca_raw = ca_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    envelope = {
        "payload": payload,
        "signer_public_key": base64.b64encode(ca_raw).decode("ascii"),
        "signature": base64.b64encode(ca_key.sign(b"NLS-DIR-v1" + cbor2.dumps(payload, canonical=True))).decode("ascii"),
        "encoding": "canonical-cbor",
        "domain": "NLS-DIR-v1",
    }
    return envelope, cert, endpoint


def _m2_or_m3(kind, sid, router_key, ca_key, rsa_key):
    envelope, cert, endpoint = _rdr_v2(router_key, ca_key, rsa_key)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    if kind == M2:
        obj = {
            "session_id": sid, "router_id": "router-v2", "certificate": cert_pem,
            "RDR": envelope, "gateway_ips": [], "sa_proposals": ["X25519-HKDF-SHA256-AES-256-GCM-Ed25519-RSA-OAEP-SHA256"],
            "dh_pub_D": os.urandom(32), "nonce_d": os.urandom(32),
            "ike_meta": {"version": 2, "nonce_s": os.urandom(32)},
            "H1": os.urandom(32), "sig_D": b"",
        }
    else:
        obj = {
            "session_id": sid, "certificate": cert_pem, "RDR": envelope,
            "dh_pub_S": os.urandom(32), "chosen_sa": "X25519-HKDF-SHA256-AES-256-GCM-Ed25519-RSA-OAEP-SHA256",
            "S.wan_endpoint": endpoint, "H2": os.urandom(32), "sig_S": b"",
        }
    return sign_v2(kind, obj, router_key), envelope, endpoint


@pytest.mark.parametrize("kind", [M2, M3], ids=["M2", "M3"])
def test_rdr_v2_positive_message_encode_decode_and_signatures(kind):
    sid = os.urandom(16)
    router_key = ed25519.Ed25519PrivateKey.generate()
    ca_key = ed25519.Ed25519PrivateKey.generate()
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    obj, rdr, _endpoint = _m2_or_m3(kind, sid, router_key, ca_key, recipient)

    packet = encode_v2_message(kind, sid, recipient.public_key(), obj)
    decoded_kind, decoded_sid, decoded, plaintext = open_v2_message(packet, recipient)
    assert (decoded_kind, decoded_sid) == (kind, sid)
    assert decoded == obj
    verify_v2_signature(kind, decoded, router_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ))
    ca_key.public_key().verify(
        base64.b64decode(rdr["signature"], validate=True),
        b"NLS-DIR-v1" + cbor2.dumps(rdr["payload"], canonical=True),
    )
    assert plaintext


@pytest.mark.parametrize("kind", [M2, M3], ids=["M2", "M3"])
@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ("unknown", "NLS_HS_RDR_PAYLOAD_FIELDS"),
        ("legacy", "NLS_HS_RDR_PAYLOAD_FIELDS"),
        ("unusable", "NLS_HS_RDR_UNUSABLE"),
    ],
)
def test_rdr_v2_rejects_unknown_legacy_and_unusable_records(kind, mutation, error):
    sid = os.urandom(16)
    router_key = ed25519.Ed25519PrivateKey.generate()
    ca_key = ed25519.Ed25519PrivateKey.generate()
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    obj, _rdr, _endpoint = _m2_or_m3(kind, sid, router_key, ca_key, recipient)
    payload = obj["RDR"]["payload"]
    if mutation == "unknown":
        payload["unapproved_extension"] = "not-allowed"
    elif mutation == "legacy":
        del payload["rdr_version"]
    else:
        payload["original_ip_usable"] = False

    with pytest.raises(ValueError, match=error):
        encode_v2_message(kind, sid, recipient.public_key(), obj)
