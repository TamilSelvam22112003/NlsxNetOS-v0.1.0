import os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from nls.handshake import (
    M4, V2_MAGIC, decode_v2_envelope, encode_v2_message, open_v2_message,
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
    with pytest.raises(ValueError):
        decode_v2_envelope(bytes(tampered))


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
