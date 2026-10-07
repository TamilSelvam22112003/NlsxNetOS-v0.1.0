import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

DEFAULT_ENCRYPTION_KEY_PATH = Path("/var/lib/nlsxnetos/identity/rsa-encryption.pem")
DEFAULT_SIGNING_KEY_PATH = Path("/var/lib/nlsxnetos/identity/rsa-signing.pem")
OAEP_HASH_SIZE = SHA256().digest_size


def _load_or_create_rsa(path, purpose):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
            raise ValueError(f"NLS RSA {purpose} key must be RSA >= 3072 bits")
        return key
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


def load_or_create(path=DEFAULT_ENCRYPTION_KEY_PATH):
    return _load_or_create_rsa(path, "encryption")


def load_or_create_signing(path=DEFAULT_SIGNING_KEY_PATH):
    return _load_or_create_rsa(path, "signing")


def load_private_key(value):
    if isinstance(value, rsa.RSAPrivateKey):
        if value.key_size < 3072:
            raise ValueError("RSA private key must be at least 3072 bits")
        return value
    if isinstance(value, (str, Path)):
        key = serialization.load_pem_private_key(Path(value).read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
            raise ValueError("RSA private key must be RSA >= 3072 bits")
        return key
    raise ValueError("invalid RSA private key")


def public_key_b64(key):
    raw = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(raw).decode("ascii")


def load_public_key(value):
    if isinstance(value, rsa.RSAPublicKey):
        if value.key_size < 3072:
            raise ValueError("RSA public key must be at least 3072 bits")
        return value
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        key = serialization.load_der_public_key(raw)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("invalid RSA public key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError("RSA public key must be RSA >= 3072 bits")
    return key


def _oaep_padding(label=b""):
    return padding.OAEP(mgf=padding.MGF1(SHA256()), algorithm=SHA256(), label=label)


def sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        SHA256(),
    )


def verify(public_key, signature, message):
    public_key.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        SHA256(),
    )


def max_plaintext_per_rsa_block(public_or_private_key):
    return public_or_private_key.key_size // 8 - (2 * OAEP_HASH_SIZE) - 2


def encrypt_chunks(public_key, plaintext, label=b""):
    if not plaintext:
        raise ValueError("cannot RSA-encrypt empty plaintext")
    block_size = max_plaintext_per_rsa_block(public_key)
    chunks = []
    for index, offset in enumerate(range(0, len(plaintext), block_size)):
        chunk_label = label + index.to_bytes(2, "big")
        chunks.append(public_key.encrypt(plaintext[offset:offset + block_size], _oaep_padding(chunk_label)))
    return b"".join(chunks)


def decrypt_chunks(private_key, ciphertext, chunk_count, label=b""):
    if not ciphertext or chunk_count < 1:
        raise ValueError("invalid RSA ciphertext")
    block_size = private_key.key_size // 8
    if len(ciphertext) != block_size * chunk_count:
        raise ValueError("RSA ciphertext does not match chunk count")
    plaintext = []
    for offset in range(0, len(ciphertext), block_size):
        index = offset // block_size
        chunk_label = label + index.to_bytes(2, "big")
        plaintext.append(private_key.decrypt(ciphertext[offset:offset + block_size], _oaep_padding(chunk_label)))
    return b"".join(plaintext)
