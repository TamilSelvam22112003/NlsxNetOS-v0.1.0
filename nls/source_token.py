"""SourceToken derivation and pinned IPv6 address policy for the NLH2 data plane.

Implements MASTER_SPEC.md amendment B.2. This module is a primitive only;
the daemon must still install/remove tokens, maintain collision-safe session
tables, and bind source/destination addresses into data-plane AEAD.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import socket
import subprocess

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.hazmat.primitives import hashes
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


def validate_original_ip(value: str | ipaddress.IPv6Address) -> ipaddress.IPv6Address:
    """Validate an RDR originalIP under the hybrid NLH2 amendment."""
    address = _ipv6(value, "originalIP")
    if (address.is_unspecified or address.is_loopback or address.is_multicast
            or address.is_link_local or address.ipv4_mapped is not None):
        raise ValueError("originalIP is not permitted by the RDR address policy")
    return address


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
    # A SourceToken is a pseudonymous routing identifier, not reversible
    # ciphertext. Use a keyed PRF to map one 128-bit address to an opaque
    # 128-bit candidate; avoid ECB, which is not an appropriate general-purpose
    # encryption mode and triggers the security scanner.
    candidate = hmac.new(
        key,
        b"NLS-SourceToken-candidate-v1/" + sender_original_ip,
        hashlib.sha256,
    ).digest()[:16]
    return ipaddress.IPv6Address(candidate)


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
    sender = validate_original_ip(sender_original_ip)
    peer = validate_original_ip(peer_original_ip)
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


COUNTER_BYTES = 8
TAG_BYTES = 16
MESSAGE_TYPE_BYTES = 1
MAX_UDP_PAYLOAD = 65527
NLD2_MAGIC = b"NLD2"
NLD2_VERSION = 2
MODE_SOURCE_ONLY = 1
MODE_SOURCE_DESTINATION = 2
NLD2_COMMON_HEADER_BYTES = 14
REKEY_COUNTER_LIMIT = 1 << 32


def _outer_ipv6(value: str | ipaddress.IPv6Address, field: str) -> ipaddress.IPv6Address:
    return _ipv6(value, field)


def _nonce(iv_prefix: bytes, counter: int) -> bytes:
    if not isinstance(iv_prefix, bytes) or len(iv_prefix) != 4:
        raise ValueError("directional IV prefix must be 4 bytes")
    if type(counter) is not int or not 0 <= counter < REKEY_COUNTER_LIMIT:
        raise ValueError("counter must be an unsigned value below the rekey limit")
    return iv_prefix + counter.to_bytes(COUNTER_BYTES, "big")


def _mode_number(metadata_mode: str) -> int:
    if metadata_mode == "source-only":
        return MODE_SOURCE_ONLY
    if metadata_mode == "source-destination":
        return MODE_SOURCE_DESTINATION
    raise ValueError("metadata_mode must be source-only or source-destination")


def _validate_inner_packet(body: bytes) -> tuple[int, bytes]:
    if not isinstance(body, bytes) or not body:
        raise ValueError("SourceToken IP packet body is empty")
    version = body[0] >> 4
    if version == 4:
        if len(body) < 20:
            raise ValueError("SourceToken inner IPv4 packet is too short")
        ihl = (body[0] & 0x0F) * 4
        if ihl < 20 or ihl > len(body) or int.from_bytes(body[2:4], "big") != len(body):
            raise ValueError("SourceToken inner IPv4 packet length invalid")
        return 4, body[16:20]
    if version == 6:
        if len(body) < 40 or int.from_bytes(body[4:6], "big") + 40 != len(body):
            raise ValueError("SourceToken inner IPv6 packet length invalid")
        return 6, body[24:40]
    raise ValueError("SourceToken inner packet version invalid")


def _visible_destination(body: bytes) -> bytes:
    version, destination = _validate_inner_packet(body)
    if version == 4:
        return bytes([4]) + (b"\x00" * 12) + destination
    return bytes([6]) + destination


def seal_source_token_payload(
    key: bytes,
    iv_prefix: bytes,
    counter: int,
    outer_source: str | ipaddress.IPv6Address,
    outer_destination: str | ipaddress.IPv6Address,
    message_body: bytes,
    *,
    message_type: int = 0,
    metadata_mode: str = "source-destination",
) -> bytes:
    """Build an NLD2 record; legacy counter-first wire format is never emitted."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("directional AES key must be 32 bytes")
    if type(message_type) is not int or message_type != 0:
        raise ValueError("only assigned message type 0 may be emitted")
    if not isinstance(message_body, bytes):
        raise ValueError("message body must be bytes")
    if type(counter) is not int or not 0 <= counter < REKEY_COUNTER_LIMIT:
        raise ValueError("counter must be an unsigned value below the rekey limit")
    mode = _mode_number(metadata_mode)
    _validate_inner_packet(message_body)
    source = _outer_ipv6(outer_source, "outer_source")
    destination = _outer_ipv6(outer_destination, "outer_destination")
    visible = _visible_destination(message_body) if mode == MODE_SOURCE_ONLY else b""
    header = NLD2_MAGIC + bytes([NLD2_VERSION, mode]) + counter.to_bytes(COUNTER_BYTES, "big") + visible
    nonce = _nonce(iv_prefix, counter)
    aad = source.packed + destination.packed + header
    ciphertext = AESGCM(key).encrypt(nonce, bytes([message_type]) + message_body, aad)
    payload = header + ciphertext
    if len(payload) > MAX_UDP_PAYLOAD:
        raise ValueError("NLD2 payload exceeds maximum IPv6 UDP payload")
    return payload


def open_source_token_payload(
    key: bytes,
    iv_prefix: bytes,
    payload: bytes,
    outer_source: str | ipaddress.IPv6Address,
    outer_destination: str | ipaddress.IPv6Address,
    *,
    metadata_mode: str = "source-destination",
) -> tuple[int, int, bytes]:
    """Authenticate and decrypt NLD2; replay state is committed by the caller afterward."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("directional AES key must be 32 bytes")
    if not isinstance(payload, bytes) or len(payload) > MAX_UDP_PAYLOAD:
        raise ValueError("NLD2 payload length invalid")
    if payload[:4] != NLD2_MAGIC:
        raise ValueError("NLD2 magic invalid; legacy formats are not accepted")
    expected_mode = _mode_number(metadata_mode)
    if len(payload) < NLD2_COMMON_HEADER_BYTES + MESSAGE_TYPE_BYTES + TAG_BYTES + 20:
        raise ValueError("NLD2 payload length invalid")
    if payload[4] != NLD2_VERSION:
        raise ValueError("NLD2 version unsupported")
    mode = payload[5]
    if mode not in (MODE_SOURCE_ONLY, MODE_SOURCE_DESTINATION):
        raise ValueError("NLD2 metadata mode invalid")
    if mode != expected_mode:
        raise ValueError("NLD2 metadata mode does not match local policy")
    counter = int.from_bytes(payload[6:14], "big")
    if counter >= REKEY_COUNTER_LIMIT:
        raise ValueError("NLD2 counter exceeds hard rekey limit")
    metadata_len = 17 if mode == MODE_SOURCE_ONLY else 0
    header_len = NLD2_COMMON_HEADER_BYTES + metadata_len
    if len(payload) < header_len + MESSAGE_TYPE_BYTES + TAG_BYTES + 20:
        raise ValueError("NLD2 payload length invalid")
    header = payload[:header_len]
    visible_destination = payload[NLD2_COMMON_HEADER_BYTES:header_len] if metadata_len else b""
    source = _outer_ipv6(outer_source, "outer_source")
    destination = _outer_ipv6(outer_destination, "outer_destination")
    aad = source.packed + destination.packed + header
    try:
        plaintext = AESGCM(key).decrypt(_nonce(iv_prefix, counter), payload[header_len:], aad)
    except InvalidTag as exc:
        raise ValueError("NLD2 authentication failed") from exc
    if not plaintext:
        raise ValueError("NLD2 plaintext is empty")
    message_type, body = plaintext[0], plaintext[1:]
    if message_type != 0:
        raise ValueError("NLD2 message type is unassigned")
    version, inner_destination = _validate_inner_packet(body)
    if mode == MODE_SOURCE_ONLY:
        expected_visible = (
            bytes([4]) + b"\x00" * 12 + inner_destination
            if version == 4 else bytes([6]) + inner_destination
        )
        if len(visible_destination) != 17 or not hmac.compare_digest(visible_destination, expected_visible):
            raise ValueError("NLD2 visible destination does not match inner packet")
    return counter, message_type, body


class SourceTokenAddressLease:
    """Own one temporary token /128 and its UDP sender socket."""

    def __init__(self, token: str, interface: str, sock):
        self.token = token
        self.interface = interface
        self.sock = sock
        self.closed = False

    def close(self) -> None:
        if self.closed:
            return
        self.sock.close()
        result = subprocess.run(
            ["ip", "-6", "addr", "del", f"{self.token}/128", "dev", self.interface],
            check=False, capture_output=True, text=True,
        )
        if result.returncode != 0:
            shown = subprocess.run(
                ["ip", "-6", "addr", "show", "dev", self.interface],
                check=True, capture_output=True, text=True,
            ).stdout
            if f"{self.token}/128" in shown or f"{self.token} " in shown:
                raise RuntimeError("unable to remove SourceToken address")
        self.closed = True


def open_source_token_socket(
    token: str | ipaddress.IPv6Address,
    peer_original_ip: str | ipaddress.IPv6Address,
    port: int,
    *,
    interface: str | None = None,
) -> SourceTokenAddressLease:
    """Assign a temporary SourceToken /128 and bind a UDP socket to its source port."""
    token_address = _ipv6(token, "SourceToken")
    peer_address = validate_original_ip(peer_original_ip)
    if not address_policy_valid(token_address):
        raise ValueError("SourceToken address violates pinned policy-v1")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("advertised UDP port must be 1..65535")
    if interface is None or interface == "":
        route = subprocess.run(
            ["ip", "-6", "route", "get", str(peer_address)],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        if "dev" not in route:
            raise RuntimeError("cannot determine interface for SourceToken sender")
        interface = route[route.index("dev") + 1]
    if (not isinstance(interface, str) or not interface or len(interface) > 15
            or "/" in interface or "\x00" in interface):
        raise ValueError("invalid SourceToken interface")
    subprocess.run(
        ["ip", "-6", "addr", "add", f"{token_address}/128", "dev", interface, "nodad"],
        check=True, capture_output=True, text=True,
    )
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "IPV6_RECVPKTINFO"):
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        if not hasattr(socket, "SO_BINDTODEVICE"):
            raise RuntimeError("SO_BINDTODEVICE is unavailable for SourceToken transport")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\x00")
        sock.bind((str(token_address), port))
        sock.setblocking(False)
        observed = subprocess.run(
            ["ip", "-6", "addr", "show", "dev", interface],
            check=True, capture_output=True, text=True,
        ).stdout
        if f"{token_address}/128" not in observed:
            raise RuntimeError("SourceToken address assignment could not be verified")
        return SourceTokenAddressLease(str(token_address), interface, sock)
    except Exception as exc:
        if sock is not None:
            sock.close()
        subprocess.run(
            ["ip", "-6", "addr", "del", f"{token_address}/128", "dev", interface],
            check=False, capture_output=True, text=True,
        )
        raise RuntimeError("unable to create SourceToken UDP sender") from exc
