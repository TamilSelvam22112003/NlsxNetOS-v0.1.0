import os
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
def generate_keypair():
    p=X25519PrivateKey.generate()
    return p.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()),p.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def derive_key(private_key,peer_public_key,salt=None):
    shared=X25519PrivateKey.from_private_bytes(private_key).exchange(X25519PublicKey.from_public_bytes(peer_public_key))
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=b"NlsxNetOS-NLS-v1").derive(shared)
def encrypt(key,plaintext,aad=b""):
    nonce=os.urandom(12); return nonce,AESGCM(key).encrypt(nonce,plaintext,aad)
def decrypt(key,nonce,ciphertext,aad=b""): return AESGCM(key).decrypt(nonce,ciphertext,aad)
