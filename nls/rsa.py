import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256


DEFAULT_ENCRYPTION_KEY_PATH = Path(
    "/var/lib/nlsxnetos/identity/rsa-encryption.pem"
)


def load_or_create(path=DEFAULT_ENCRYPTION_KEY_PATH):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return serialization.load_pem_private_key(
            path.read_bytes(), password=None
        )
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    raw = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(raw)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def public_key_b64(key):
    raw = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(raw).decode("ascii")


def load_public_key(value):
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        key = serialization.load_der_public_key(raw)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("invalid RSA encryption public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Router-CA encryption key must be RSA")
    if key.key_size < 2048:
        raise ValueError("RSA encryption key must be at least 2048 bits")
    return key


def wrap_key(public_key, data_key):
    return public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None,
        ),
    )


def unwrap_key(private_key, wrapped_key):
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None,
        ),
    )
