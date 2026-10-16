"""NLE2 authenticated data-plane encapsulation.

The fixed 32-byte header contains no inner addresses. The entire header is
AAD; packet contents (including the inner IP header) are encrypted with the
directional AES-256-GCM session key negotiated by NLH2. No per-packet key
generation or RSA wrapping is performed.
"""
from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .replay import MAX_SEQUENCE

MAGIC = b"NLE2"
VERSION = 2
HEADER = struct.Struct("!4sB3s16sQ")
HEADER_SIZE = 32
TAG_SIZE = 16
IV_PREFIX_SIZE = 4
MAX_PACKETS_PER_KEY = 1 << 32
MAX_INNER_PACKET = 65527 - HEADER_SIZE - TAG_SIZE
_ZERO_FLAGS = bytes(3)


def _validate_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("NLE2 session key must be 32 bytes")


def _validate_prefix(iv_prefix: bytes) -> None:
    if not isinstance(iv_prefix, (bytes, bytearray)) or len(iv_prefix) != IV_PREFIX_SIZE:
        raise ValueError("NLE2 IV prefix must be 4 bytes")


def _validate_session_id(session_id: bytes) -> None:
    if not isinstance(session_id, bytes) or len(session_id) != 16:
        raise ValueError("NLE2 session_id must be 16 bytes")


def _nonce(iv_prefix: bytes, sequence: int) -> bytes:
    if (isinstance(sequence, bool) or not isinstance(sequence, int)
            or sequence < 0 or sequence > MAX_SEQUENCE):
        raise ValueError("NLE2 sequence must be an unsigned 64-bit integer")
    if sequence >= MAX_PACKETS_PER_KEY:
        raise ValueError("NLE2 key packet limit reached; rekey required")
    return bytes(iv_prefix) + sequence.to_bytes(8, "big")


def _parse_header(packet: bytes, expected_session_id: bytes) -> tuple[int, bytes]:
    _validate_session_id(expected_session_id)
    if not isinstance(packet, bytes) or len(packet) < HEADER_SIZE + TAG_SIZE:
        raise ValueError("NLE2 packet is too short")
    if len(packet) > 65527:
        raise ValueError("NLE2 packet exceeds maximum IPv6 UDP payload")
    magic, version, flags, session_id, sequence = HEADER.unpack_from(packet)
    if magic != MAGIC or version != VERSION or flags != _ZERO_FLAGS:
        raise ValueError("NLE2 header invalid")
    if session_id != expected_session_id:
        raise ValueError("NLE2 wrong session")
    if sequence >= MAX_PACKETS_PER_KEY:
        raise ValueError("NLE2 key packet limit reached; rekey required")
    return sequence, packet[:HEADER_SIZE]


def seal_ip_packet(session_key: bytes, session_id: bytes, sequence: int,
                   iv_prefix: bytes, packet: bytes) -> bytes:
    """Seal one inner IP packet using a directional session key."""
    _validate_key(session_key)
    _validate_session_id(session_id)
    _validate_prefix(iv_prefix)
    if not isinstance(packet, bytes) or not packet or len(packet) > MAX_INNER_PACKET:
        raise ValueError("NLE2 inner packet length invalid")
    nonce = _nonce(iv_prefix, sequence)
    header = HEADER.pack(MAGIC, VERSION, _ZERO_FLAGS, session_id, sequence)
    return header + AESGCM(bytes(session_key)).encrypt(nonce, packet, header)


def open_ip_packet(session_key: bytes, packet: bytes, expected_session_id: bytes,
                   iv_prefix: bytes) -> bytes:
    """Authenticate and decrypt one NLE2 packet; replay marking is caller-owned."""
    _validate_key(session_key)
    _validate_prefix(iv_prefix)
    sequence, header = _parse_header(packet, expected_session_id)
    nonce = _nonce(iv_prefix, sequence)
    try:
        plaintext = AESGCM(bytes(session_key)).decrypt(nonce, packet[HEADER_SIZE:], header)
    except InvalidTag as exc:
        raise ValueError("NLE2 authentication failed") from exc
    if not plaintext or len(plaintext) > MAX_INNER_PACKET:
        raise ValueError("NLE2 plaintext length invalid")
    # Reject malformed/non-IP plaintext before it can reach the TUN.
    version = plaintext[0] >> 4
    if version == 4:
        if len(plaintext) < 20 or (plaintext[0] & 0x0F) < 5:
            raise ValueError("NLE2 inner IPv4 header invalid")
        ihl = (plaintext[0] & 0x0F) * 4
        total_length = int.from_bytes(plaintext[2:4], "big")
        if ihl > len(plaintext) or total_length != len(plaintext) or total_length < ihl:
            raise ValueError("NLE2 inner IPv4 length invalid")
    elif version == 6:
        if len(plaintext) < 40 or int.from_bytes(plaintext[4:6], "big") + 40 != len(plaintext):
            raise ValueError("NLE2 inner IPv6 length invalid")
    else:
        raise ValueError("NLE2 inner IP version invalid")
    return plaintext
