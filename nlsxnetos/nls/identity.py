import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_IDENTITY_PATH = Path("/var/lib/nlsxnetos/identity/ed25519.key")

def load_or_create(path=DEFAULT_IDENTITY_PATH):
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    if p.exists():
        raw=p.read_bytes()
        if len(raw)!=32: raise ValueError("invalid Ed25519 identity key length")
        return Ed25519PrivateKey.from_private_bytes(raw)
    key=Ed25519PrivateKey.generate()
    raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    tmp=p.with_suffix(".tmp"); tmp.write_bytes(raw); os.chmod(tmp,0o600); os.replace(tmp,p); os.chmod(p,0o600)
    return key

def b64(data): return base64.b64encode(data).decode("ascii")
def unb64(value): return base64.b64decode(value.encode("ascii"),validate=True)
def public_key_b64(key): return b64(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
def decode_public_key(value):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(unb64(value))
