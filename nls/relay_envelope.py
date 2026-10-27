"""Experimental per-hop authenticated relay envelope primitives.

This module is deliberately NOT wired into NLSDaemon yet. It is a building
block for the versioned multi-hop profile; deploying it alone does not enable
metadata confidentiality. Each hop must use a distinct, authenticated key.
"""
from __future__ import annotations

import ipaddress
import secrets
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"NLR1"
VERSION = 1
TOKEN_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
# magic, version, flags, hop-scoped opaque token, sequence, nonce, ciphertext length
_HEADER = struct.Struct("!4sBB16sQ12sI")
# next-hop family/address, UDP port, inner length, encrypted previous-hop source family/address
_INNER = struct.Struct("!B16sHIB16s")
_IPV4 = 4
_IPV6 = 6
# Conservative maximum UDP payload; account for both framing headers and the AEAD tag.
_MAX_UDP_PAYLOAD = 65507
_MAX_INNER = _MAX_UDP_PAYLOAD - _HEADER.size - _INNER.size - TAG_SIZE
_MAX_CIPHERTEXT = _INNER.size + _MAX_INNER + TAG_SIZE


class RelayEnvelopeError(ValueError):
    """Raised when a relay envelope is malformed or fails authentication."""


@dataclass(frozen=True)
class RelayLayer:
    """Authenticated plaintext for one relay, never the original endpoint packet."""

    next_hop_address: str
    next_hop_port: int
    previous_hop_source_locator: str
    inner_envelope: bytes
    sequence: int
    hop_token: bytes


def _key_bytes(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise RelayEnvelopeError("relay key must be exactly 32 bytes")
    return key


def _token_bytes(token: bytes) -> bytes:
    if not isinstance(token, bytes) or len(token) != TOKEN_SIZE:
        raise RelayEnvelopeError("hop token must be exactly 16 bytes")
    return token


def _encode_locator(address: str) -> tuple[int, bytes]:
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError) as exc:
        raise RelayEnvelopeError("source locator must be an IP literal") from exc
    if ip.is_unspecified or ip.is_multicast:
        raise RelayEnvelopeError("source locator must be a unicast address")
    if ip.version == 4:
        return _IPV4, ip.packed + bytes(12)
    return _IPV6, ip.packed


def _decode_locator(family: int, packed_address: bytes, field: str) -> str:
    if family == _IPV4:
        if packed_address[4:] != bytes(12):
            raise RelayEnvelopeError(f"non-canonical IPv4 {field}")
        address = str(ipaddress.IPv4Address(packed_address[:4]))
    elif family == _IPV6:
        address = str(ipaddress.IPv6Address(packed_address))
    else:
        raise RelayEnvelopeError(f"unsupported {field} address family")
    ip = ipaddress.ip_address(address)
    if ip.is_unspecified or ip.is_multicast:
        raise RelayEnvelopeError(f"invalid {field} unicast address")
    return address


def _encode_next_hop(address: str, port: int) -> tuple[int, bytes]:
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError) as exc:
        raise RelayEnvelopeError("next-hop address must be an IP literal") from exc
    if ip.is_unspecified or ip.is_multicast:
        raise RelayEnvelopeError("next-hop address must be a unicast locator")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise RelayEnvelopeError("next-hop UDP port must be in 1..65535")
    if ip.version == 4:
        return _IPV4, ip.packed + bytes(12)
    return _IPV6, ip.packed


def seal_relay_layer(
    key: bytes,
    hop_token: bytes,
    sequence: int,
    next_hop_address: str,
    next_hop_port: int,
    inner_envelope: bytes,
    *,
    previous_hop_source_locator: str,
    nonce: bytes | None = None,
) -> bytes:
    """Seal one relay layer; cleartext contains no next-hop or endpoint locator.

    The caller MUST ensure sequence numbers are monotonic within the key's
    lifetime and MUST never reuse a nonce with the same key. Random nonces are
    provided by default; a durable counter-based nonce policy is preferable
    for high-volume deployments.
    """
    key = _key_bytes(key)
    token = _token_bytes(hop_token)
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence < 2**64:
        raise RelayEnvelopeError("sequence must be an unsigned 64-bit integer")
    if not isinstance(inner_envelope, bytes) or len(inner_envelope) > _MAX_INNER:
        raise RelayEnvelopeError("inner envelope must be bytes within the UDP payload limit")
    family, packed_address = _encode_next_hop(next_hop_address, next_hop_port)
    source_family, packed_source = _encode_locator(previous_hop_source_locator)
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_SIZE)
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
        raise RelayEnvelopeError("nonce must be exactly 12 bytes")
    plaintext = _INNER.pack(family, packed_address, next_hop_port, len(inner_envelope), source_family, packed_source) + inner_envelope
    ciphertext_length = len(plaintext) + TAG_SIZE
    header = _HEADER.pack(MAGIC, VERSION, 0, token, sequence, nonce, ciphertext_length)
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


def open_relay_layer(
    key: bytes,
    packet: bytes,
    *,
    expected_hop_token: bytes,
    expected_sequence: int | None = None,
) -> RelayLayer:
    """Authenticate/decrypt exactly one relay layer; never recursively decrypts."""
    key = _key_bytes(key)
    expected_hop_token = _token_bytes(expected_hop_token)
    if not isinstance(packet, bytes) or len(packet) < _HEADER.size + _INNER.size + TAG_SIZE:
        raise RelayEnvelopeError("relay envelope is truncated")
    try:
        magic, version, flags, token, sequence, nonce, ciphertext_length = _HEADER.unpack_from(packet)
    except struct.error as exc:
        raise RelayEnvelopeError("invalid relay header") from exc
    if magic != MAGIC or version != VERSION or flags != 0:
        raise RelayEnvelopeError("unsupported relay envelope header")
    if not secrets.compare_digest(token, expected_hop_token):
        raise RelayEnvelopeError("hop token mismatch")
    if expected_sequence is not None and sequence != expected_sequence:
        raise RelayEnvelopeError("sequence mismatch")
    if ciphertext_length < _INNER.size + TAG_SIZE or ciphertext_length > _MAX_CIPHERTEXT:
        raise RelayEnvelopeError("invalid ciphertext length")
    if len(packet) != _HEADER.size + ciphertext_length:
        raise RelayEnvelopeError("relay envelope length mismatch")
    try:
        plaintext = AESGCM(key).decrypt(nonce, packet[_HEADER.size:], packet[:_HEADER.size])
    except (InvalidTag, ValueError) as exc:
        raise RelayEnvelopeError("relay envelope authentication failed") from exc
    if len(plaintext) < _INNER.size:
        raise RelayEnvelopeError("relay plaintext is truncated")
    family, packed_address, port, inner_length, source_family, packed_source = _INNER.unpack_from(plaintext)
    if inner_length > _MAX_INNER or len(plaintext) != _INNER.size + inner_length:
        raise RelayEnvelopeError("inner envelope length mismatch")
    if not 1 <= port <= 65535:
        raise RelayEnvelopeError("invalid next-hop port")
    address = _decode_locator(family, packed_address, "next-hop locator")
    previous_source = _decode_locator(source_family, packed_source, "previous-hop source locator")
    return RelayLayer(address, port, previous_source, plaintext[_INNER.size:], sequence, token)
