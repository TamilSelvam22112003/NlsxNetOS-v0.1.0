"""Temporary NLS Virtual Identity (vIP) trust exchange primitives."""
import base64
import hashlib
import ipaddress
import json
from .rsa import load_public_key, load_private_key, encrypt_chunks, decrypt_chunks, max_plaintext_per_rsa_block

VIP_VERSION = 1
VIP_LIFETIME_SECONDS = 120
VIP_LABEL = b"NLS-vIP-v1|"

def generate_vip(router_id, peer_id, nonce):
    token = hashlib.sha512(
        f"{VIP_VERSION}|{router_id}|{peer_id}|{nonce}".encode()
    ).hexdigest()
    raw = bytearray.fromhex(token[:32])
    raw[0] = (raw[0] & 0x0F) | 0xF0
    return token, str(ipaddress.IPv6Address(bytes(raw)))

def encrypt(public_key, obj):
    key = load_public_key(public_key)
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    block = max_plaintext_per_rsa_block(key)
    count = (len(data) + block - 1) // block
    ciphertext = encrypt_chunks(key, data, label=VIP_LABEL)
    return {"chunks": count, "ciphertext": base64.b64encode(ciphertext).decode("ascii")}

def decrypt(private_key, envelope):
    key = load_private_key(private_key)
    count = int(envelope["chunks"])
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    data = decrypt_chunks(key, ciphertext, count, label=VIP_LABEL)
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
