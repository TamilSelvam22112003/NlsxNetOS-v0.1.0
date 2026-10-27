"""End-to-end endpoint envelope for NLS.

The endpoint envelope encrypts the original IP packet to the destination
router's RSA encryption key and signs the complete envelope with the source
router's Ed25519 identity key. Relays carry this object as opaque bytes inside
NLR1 and must not decrypt it.
"""
from __future__ import annotations

import ipaddress
import secrets
import struct
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .rsa import load_public_key, unwrap_key, wrap_key

MAGIC = b"NLE2"
VERSION = 1
SIGNATURE_SIZE = 64
HEADER = struct.Struct("!4sB16s32sQQ12sH")
HEADER_SIZE = HEADER.size
_MAX_PACKET = 65507


class EndpointEnvelopeError(ValueError):
    """Raised when an endpoint envelope is malformed or fails verification."""


def _inner_destination(packet: bytes) -> str:
    if not isinstance(packet, bytes) or not packet:
        raise EndpointEnvelopeError("endpoint packet must be non-empty bytes")
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            raise EndpointEnvelopeError("IPv4 endpoint packet is truncated")
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            raise EndpointEnvelopeError("invalid IPv4 endpoint header")
        return str(ipaddress.IPv4Address(packet[16:20]))
    if version == 6:
        if len(packet) < 40:
            raise EndpointEnvelopeError("IPv6 endpoint packet is truncated")
        return str(ipaddress.IPv6Address(packet[24:40]))
    raise EndpointEnvelopeError("unsupported endpoint IP version")


def _destination_field(address: str) -> tuple[int, bytes]:
    ip = ipaddress.ip_address(address)
    if ip.is_unspecified or ip.is_multicast:
        raise EndpointEnvelopeError("endpoint destination must be a unicast address")
    if ip.version == 4:
        return 4, ip.packed + bytes(12)
    return 6, ip.packed


def _decode_destination(version: int, packed: bytes) -> str:
    if version == 4:
        if packed[4:] != bytes(12):
            raise EndpointEnvelopeError("non-canonical IPv4 destination")
        return str(ipaddress.IPv4Address(packed[:4]))
    if version == 6:
        return str(ipaddress.IPv6Address(packed))
    raise EndpointEnvelopeError("unsupported endpoint destination family")


def _identity_raw(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) if isinstance(key, Ed25519PrivateKey) else key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def seal_endpoint_packet(
    destination_encryption_key,
    source_identity_key: Ed25519PrivateKey,
    session_id: bytes,
    sequence: int,
    destination_address: str,
    original_packet: bytes,
    *,
    timestamp: int | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Encrypt to the destination router and sign as the authenticated origin."""
    if not isinstance(source_identity_key, Ed25519PrivateKey):
        raise EndpointEnvelopeError("source identity key must be an Ed25519 private key")
    if not isinstance(session_id, bytes) or len(session_id) != 16:
        raise EndpointEnvelopeError("session_id must be exactly 16 bytes")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence < 2**64:
        raise EndpointEnvelopeError("sequence must be an unsigned 64-bit integer")
    if len(original_packet) > _MAX_PACKET - HEADER_SIZE - 384 - 16 - SIGNATURE_SIZE:
        raise EndpointEnvelopeError("endpoint packet exceeds safe UDP envelope size")
    _destination_field(destination_address)  # validate destination; address remains encrypted in the IP packet\n    if _inner_destination(original_packet) != str(ipaddress.ip_address(destination_address)):
        raise EndpointEnvelopeError("endpoint destination does not match original IP packet")
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    nonce = secrets.token_bytes(12) if nonce is None else nonce
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise EndpointEnvelopeError("nonce must be exactly 12 bytes")
    public_key = load_public_key(destination_encryption_key) if isinstance(destination_encryption_key, str) else destination_encryption_key
    data_key = secrets.token_bytes(32)
    wrapped_key = wrap_key(public_key, data_key)
    if not 256 <= len(wrapped_key) <= 1024:
        raise EndpointEnvelopeError("unsupported RSA wrapped-key length")
    header = HEADER.pack(
        MAGIC, VERSION, ip_version, session_id, packed_destination,
        _identity_raw(source_identity_key), sequence, timestamp, nonce,
        len(wrapped_key),
    )
    ciphertext = AESGCM(data_key).encrypt(nonce, original_packet, header)
    unsigned = header + wrapped_key + ciphertext
    signature = source_identity_key.sign(unsigned)
    return unsigned + signature


def open_endpoint_packet(
    destination_encryption_private_key,
    trusted_source_identity_key: Ed25519PublicKey,
    packet: bytes,
    *,
    expected_destination: str | None = None,
    expected_session_id: bytes | None = None,
    max_clock_skew: int = 120,
) -> dict:
    """Verify the Router-CA-trusted origin signature before decrypting payload."""
    if not isinstance(trusted_source_identity_key, Ed25519PublicKey):
        raise EndpointEnvelopeError("trusted source identity must be an Ed25519 public key")
    if not isinstance(packet, bytes) or len(packet) < HEADER_SIZE + 256 + 16 + SIGNATURE_SIZE:
        raise EndpointEnvelopeError("endpoint envelope is truncated")
    try:
        (magic, version, ip_version, session_id, packed_destination, source_identity,
         sequence, timestamp, nonce, wrapped_length) = HEADER.unpack_from(packet)
    except struct.error as exc:
        raise EndpointEnvelopeError("invalid endpoint header") from exc
    if magic != MAGIC or version != VERSION:
        raise EndpointEnvelopeError("unsupported endpoint envelope")
    if source_identity != _identity_raw(trusted_source_identity_key):
        raise EndpointEnvelopeError("endpoint source identity does not match trusted Router-CA key")
    if expected_session_id is not None and session_id != expected_session_id:
        raise EndpointEnvelopeError("endpoint session binding mismatch")
    if abs(int(time.time()) - timestamp) > max_clock_skew:
        raise EndpointEnvelopeError("endpoint timestamp outside allowed clock skew")
    if not 256 <= wrapped_length <= 1024:
        raise EndpointEnvelopeError("invalid RSA wrapped-key length")
    wrapped_end = HEADER_SIZE + wrapped_length
    signature_start = len(packet) - SIGNATURE_SIZE
    if wrapped_end + 16 > signature_start:
        raise EndpointEnvelopeError("endpoint ciphertext is truncated")
    destination = _decode_destination(ip_version, packed_destination)
    if expected_destination is not None and destination != str(ipaddress.ip_address(expected_destination)):
        raise EndpointEnvelopeError("endpoint destination binding mismatch")
    unsigned = packet[:signature_start]
    try:
        trusted_source_identity_key.verify(packet[signature_start:], unsigned)
    except InvalidSignature as exc:
        raise EndpointEnvelopeError("endpoint origin signature verification failed") from exc
    try:
        data_key = unwrap_key(destination_encryption_private_key, packet[HEADER_SIZE:wrapped_end])
        if len(data_key) != 32:
            raise EndpointEnvelopeError("invalid endpoint data key")
        plaintext = AESGCM(data_key).decrypt(nonce, packet[wrapped_end:signature_start], packet[:HEADER_SIZE])
    except (InvalidTag, ValueError) as exc:
        raise EndpointEnvelopeError("endpoint ciphertext authentication failed") from exc
    if _inner_destination(plaintext) != destination:
        raise EndpointEnvelopeError("inner/outer endpoint destination mismatch")
    return {
        "destination_ip": destination,
        "source_identity": source_identity,
        "session_id": session_id,
        "sequence": sequence,
        "timestamp": timestamp,
        "payload": plaintext,
    }
