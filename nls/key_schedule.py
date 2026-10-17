"""NLS v2 transcript hashing and directional key schedule."""
from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

DOMAIN = b"NLS-HS2"
KEY_BYTES = 32
IV_PREFIX_BYTES = 4


def transcript_hash(*messages: bytes) -> bytes:
    """Hash length-prefixed transcript messages to prevent concatenation ambiguity."""
    digest = hashlib.sha256()
    digest.update(DOMAIN)
    for message in messages:
        if not isinstance(message, bytes) or len(message) > 20 * 1024:
            raise ValueError("invalid transcript element")
        digest.update(len(message).to_bytes(4, "big"))
        digest.update(message)
    return digest.digest()


def derive_session_keys(private_key: X25519PrivateKey, peer_public: bytes,
                        h3: bytes, session_id: bytes) -> dict[str, bytes]:
    if len(session_id) != 16 or len(h3) != 32 or len(peer_public) != 32:
        raise ValueError("invalid key-schedule input length")
    if not isinstance(private_key, X25519PrivateKey):
        raise ValueError("invalid local X25519 private key")
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid X25519 public key") from exc
    if hmac.compare_digest(shared, bytes(len(shared))):
        raise ValueError("all-zero X25519 shared secret rejected")
    # HKDF's salt commits to the full handshake transcript and session identity.
    salt = hashlib.sha256(DOMAIN + session_id + h3).digest()
    material = HKDF(algorithm=hashes.SHA256(), length=104, salt=salt,
                    info=DOMAIN + b" key schedule v2").derive(shared)
    # Independent labels are derived from a PRK rather than slicing one opaque
    # key blob. Each label has a fixed, documented output length.
    prk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=DOMAIN + b" extract v2").derive(shared)
    def expand(label: bytes, length: int) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=length, salt=prk,
                    info=DOMAIN + b" " + label).derive(material[:32])
    return {
        "k_confirm": expand(b"k_confirm", 32),
        "s_to_d_key": expand(b"s_to_d_key", KEY_BYTES),
        "d_to_s_key": expand(b"d_to_s_key", KEY_BYTES),
        "s_to_d_iv_prefix": expand(b"s_to_d_iv_prefix", IV_PREFIX_BYTES),
        "d_to_s_iv_prefix": expand(b"d_to_s_iv_prefix", IV_PREFIX_BYTES),
    }


def confirmation_mac(k_confirm: bytes, h3: bytes) -> bytes:
    if len(k_confirm) != 32 or len(h3) != 32:
        raise ValueError("invalid confirmation input length")
    return hmac.new(k_confirm, DOMAIN + b" M4 confirm " + h3, hashlib.sha256).digest()
