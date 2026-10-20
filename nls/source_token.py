"""SourceToken derivation and pinned IPv6 address policy for the NLH2 data plane.

Implements MASTER_SPEC.md amendment B.2. This module is a primitive only;
the daemon must still install/remove tokens, maintain collision-safe session
tables, and bind source/destination addresses into data-plane AEAD.
"""
from __future__ import annotations

import ipaddress

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

POLICY_VERSION = 1
SOURCE_TOKEN_ATTEMPTS = 256
DOMAIN = b"NLS-SourceToken-v1/"
GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")

# Pinned policy-v1 exclusion table from MASTER_SPEC.md. Do not consult host
# IANA registry data at runtime; a change requires a protocol policy version.
POLICY_V1_EXCLUSIONS = tuple(ipaddress.IPv6Network(value) for value in (
    "2001::/23",
    "2001::/32",
    "2001:1::1/128",
    "2001:1::2/128",
    "2001:1::3/128",
    "2001:2::/48",
    "2001:3::/32",
    "2001:4:112::/48",
    "2001:10::/28",
    "2001:20::/28",
    "2001:30::/28",
    "2001:db8::/32",
    "2002::/16",
    "2620:4f:8000::/48",
    "3fff::/20",
))


def _ipv6(value: str | ipaddress.IPv6Address, field: str) -> ipaddress.IPv6Address:
    try:
        address = ipaddress.IPv6Address(value)
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError(f"{field} must be an IPv6 address") from exc
    if isinstance(value, str) and "%" in value:
        raise ValueError(f"{field} must not contain a zone identifier")
    return address


def address_policy_valid(value: str | ipaddress.IPv6Address, policy_version: int = POLICY_VERSION) -> bool:
    """Return whether an address is permitted by the pinned vIP/SourceToken policy."""
    if type(policy_version) is not int or policy_version != POLICY_VERSION:
        raise ValueError("unsupported IPv6 address policy version")
    try:
        address = _ipv6(value, "candidate")
    except ValueError:
        return False
    return address in GLOBAL_UNICAST and not any(address in network for network in POLICY_V1_EXCLUSIONS)


def _candidate(session_secret: bytes, handshake_salt: bytes, sender_original_ip: bytes,
               direction: str, attempt: int) -> ipaddress.IPv6Address:
    if not isinstance(session_secret, bytes) or len(session_secret) < 16:
        raise ValueError("session_secret must contain at least 16 bytes")
    if not isinstance(handshake_salt, bytes) or len(handshake_salt) != 32:
        raise ValueError("handshake_salt must be 32 bytes")
    if not isinstance(sender_original_ip, bytes) or len(sender_original_ip) != 16:
        raise ValueError("sender_original_ip must be 16 packed IPv6 bytes")
    if direction not in ("A-to-B", "B-to-A"):
        raise ValueError("direction must be A-to-B or B-to-A")
    if type(attempt) is not int or not 0 <= attempt < SOURCE_TOKEN_ATTEMPTS:
        raise ValueError("attempt must be an integer in 0..255")

    info = DOMAIN + direction.encode("ascii") + attempt.to_bytes(4, "big")
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=handshake_salt, info=info).derive(session_secret)
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encrypted = encryptor.update(sender_original_ip) + encryptor.finalize()
    return ipaddress.IPv6Address(encrypted)


def derive_source_token(
    session_secret: bytes,
    handshake_salt: bytes,
    sender_original_ip: str | ipaddress.IPv6Address,
    peer_original_ip: str | ipaddress.IPv6Address,
    retired_vip: str | ipaddress.IPv6Address,
    direction: str,
    *,
    policy_version: int = POLICY_VERSION,
) -> ipaddress.IPv6Address:
    """Derive a deterministic per-direction token, redrawing attempts 0..255.

    The inputs sender_original_ip, peer_original_ip, and retired_vip are used
    only for the normative collision exclusions. originalIP values must be
    canonicalizable IPv6 addresses; RDR/certificate validity is the caller's job.
    """
    if type(policy_version) is not int or policy_version != POLICY_VERSION:
        raise ValueError("unsupported IPv6 address policy version")
    sender = _ipv6(sender_original_ip, "sender_original_ip")
    peer = _ipv6(peer_original_ip, "peer_original_ip")
    retired = _ipv6(retired_vip, "retired_vip")
    if sender == peer:
        raise ValueError("router originalIP values must differ")

    for attempt in range(SOURCE_TOKEN_ATTEMPTS):
        candidate = _candidate(session_secret, handshake_salt, sender.packed, direction, attempt)
        if not address_policy_valid(candidate, policy_version):
            continue
        if candidate in (sender, peer, retired):
            continue
        return candidate
    raise ValueError("SourceToken derivation exhausted attempts 0..255")
