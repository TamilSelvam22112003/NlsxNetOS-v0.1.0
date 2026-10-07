"""NLS temporary Virtual Identity (vIP) trust exchange helpers.

vIP is a temporary IPv6 identity derived from a SHA-512 digest. The full
128-hex-character digest is retained as the vIP token; the routable vIP form
uses the first 128 bits under the ULA fd00::/8 space.
"""
import hashlib
import ipaddress
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

VIP_VERSION = 1
VIP_LIFETIME_SECONDS = 120

def generate_vip(router_id, peer_id, nonce):
    material = f"{VIP_VERSION}|{router_id}|{peer_id}|{nonce}".encode()
    token = hashlib.sha512(material).hexdigest()
    raw = bytearray.fromhex(token[:32])
    raw[0] = (raw[0] & 0x0F) | 0xF0
    return token, str(ipaddress.IPv6Address(bytes(raw)))

def _load_public(value):
    if isinstance(value, str):
        return serialization.load_pem_public_key(value.encode())
    return value

def _load_private(value):
    if isinstance(value, str):
        return serialization.load_pem_private_key(value.encode(), password=None)
    return value

def encrypt(public_key, obj):
    key = _load_public(public_key)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return key.encrypt(data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"NLS-vIP-v1"))

def decrypt(private_key, ciphertext):
    key = _load_private(private_key)
    data = key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"NLS-vIP-v1"))
    return json.loads(data.decode())

def trust_record(*, vip_token, original_ip, public_key, certificate, timestamp, trust):
    return {
        "vip_version": VIP_VERSION,
        "vip_token": vip_token,
        "original_ip": str(ipaddress.ip_address(original_ip)),
        "public_key": public_key,
        "certificate": certificate,
        "timestamp": int(timestamp),
        "trust": bool(trust),
    }
