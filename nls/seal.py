"""Bounded SEAL/OPEN hybrid envelope for NLS handshake datagrams.

SEAL = wrapped AES-256 key || nonce || AES-GCM ciphertext. The wrapped-key
length is encoded as uint16. Callers must supply protocol AAD that binds the
envelope to its datagram header. All attacker-controlled parsing failures are
normalized to SealError.
"""
from __future__ import annotations

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_PLAINTEXT = 16 * 1024
MAX_SEAL = 20 * 1024
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
_LENGTH = struct.Struct("!H")


class SealError(ValueError):
    """A malformed, oversized, or unauthenticated SEAL envelope."""


def _public_key(key):
    if isinstance(key, rsa.RSAPublicKey):
        result = key
    elif isinstance(key, (bytes, str)):
        raw = key.encode("ascii") if isinstance(key, str) else key
        try:
            result = serialization.load_pem_public_key(raw)
        except (ValueError, TypeError):
            try:
                result = serialization.load_der_public_key(raw)
            except (ValueError, TypeError) as exc:
                raise SealError("invalid RSA public key") from exc
    else:
        raise SealError("unsupported RSA public-key type")
    if not isinstance(result, rsa.RSAPublicKey) or result.key_size < 3072:
        raise SealError("RSA public key must be at least 3072 bits")
    return result


def _private_key(key):
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        raise SealError("RSA private key must be at least 3072 bits")
    return key


def seal(public_key, plaintext: bytes, aad: bytes) -> bytes:
    """Seal bytes using RSA-OAEP-SHA256 and AES-256-GCM."""
    try:
        if not isinstance(plaintext, bytes) or len(plaintext) > MAX_PLAINTEXT:
            raise SealError("plaintext length outside permitted bounds")
        if not isinstance(aad, bytes) or len(aad) > 256:
            raise SealError("AAD length outside permitted bounds")
        pub = _public_key(public_key)
        key, nonce = os.urandom(KEY_BYTES), os.urandom(NONCE_BYTES)
        wrapped = pub.encrypt(
            key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=b"NLS-SEAL-v1"),
        )
        if len(wrapped) > 65535:
            raise SealError("wrapped key too large")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        out = _LENGTH.pack(len(wrapped)) + wrapped + nonce + ciphertext
        if len(out) > MAX_SEAL:
            raise SealError("sealed envelope too large")
        return out
    except SealError:
        raise
    except Exception as exc:
        raise SealError("SEAL operation failed") from exc


def open_seal(private_key, envelope: bytes, aad: bytes) -> bytes:
    """Open a bounded envelope. No malformed hostile input escapes as a crypto exception."""
    try:
        if not isinstance(envelope, bytes) or len(envelope) < 2 + 384 + NONCE_BYTES + TAG_BYTES:
            raise SealError("sealed envelope too short")
        if len(envelope) > MAX_SEAL:
            raise SealError("sealed envelope too large")
        if not isinstance(aad, bytes) or len(aad) > 256:
            raise SealError("AAD length outside permitted bounds")
        priv = _private_key(private_key)
        wrapped_len = _LENGTH.unpack(envelope[:2])[0]
        expected = (priv.key_size + 7) // 8
        if wrapped_len != expected:
            raise SealError("wrapped-key length does not match RSA key")
        start = 2
        end = start + wrapped_len
        if end + NONCE_BYTES + TAG_BYTES > len(envelope):
            raise SealError("truncated sealed envelope")
        wrapped, nonce = envelope[start:end], envelope[end:end + NONCE_BYTES]
        ciphertext = envelope[end + NONCE_BYTES:]
        if len(ciphertext) < TAG_BYTES or len(ciphertext) > MAX_PLAINTEXT + TAG_BYTES:
            raise SealError("ciphertext length outside permitted bounds")
        key = priv.decrypt(
            wrapped,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=b"NLS-SEAL-v1"),
        )
        if len(key) != KEY_BYTES:
            raise SealError("invalid content-encryption key")
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except SealError:
        raise
    except (ValueError, TypeError, InvalidTag, OverflowError) as exc:
        raise SealError("sealed envelope authentication failed") from exc
    except Exception as exc:
        raise SealError("OPEN operation failed") from exc


# Uppercase aliases match the protocol terminology.
SEAL = seal
OPEN = open_seal
