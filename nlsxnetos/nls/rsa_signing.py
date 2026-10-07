import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

DEFAULT_SIGNING_KEY_PATH = Path("/var/lib/nlsxnetos/identity/rsa-signing.pem")


def load_or_create(path=DEFAULT_SIGNING_KEY_PATH):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("NLS RSA signing key must be RSA >= 2048 bits")
        return key
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(raw)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def load_private_key(value):
    if isinstance(value, rsa.RSAPrivateKey):
        key = value
    elif isinstance(value, (str, Path)):
        key = serialization.load_pem_private_key(Path(value).read_bytes(), password=None)
    else:
        raise ValueError("invalid RSA signing private key")
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError("RSA signing key must be RSA >= 2048 bits")
    return key


def public_key_b64(key):
    raw = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(raw).decode("ascii")


def load_public_key(value):
    if isinstance(value, rsa.RSAPublicKey):
        key = value
    else:
        try:
            raw = base64.b64decode(value.encode("ascii"), validate=True)
            key = serialization.load_der_public_key(raw)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise ValueError("invalid RSA signing public key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise ValueError("RSA signing public key must be RSA >= 2048 bits")
    return key


def sign(private_key, message):
    key = load_private_key(private_key)
    return key.sign(message, padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH), SHA256())


def verify(public_key, signature, message):
    key = load_public_key(public_key)
    key.verify(signature, message, padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH), SHA256())
