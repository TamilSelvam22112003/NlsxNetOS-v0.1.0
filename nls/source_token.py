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
DATA_MAGIC = b"NLD2"
DATA_VERSION = 2
BASE_HEADER_BYTES = 4 + 1 + 1 + COUNTER_BYTES
VISIBLE_DESTINATION_BYTES = 17
METADATA_MODE_CODES = {"source-only": 1, "source-destination": 2}
METADATA_CODE_MODES = {value: key for key, value in METADATA_MODE_CODES.items()}


def _outer_ipv6(value: str | ipaddress.IPv6Address, field: str) -> ipaddress.IPv6Address:
    return _ipv6(value, field)


def _mode_code(metadata_mode: str) -> int:
    if not isinstance(metadata_mode, str) or metadata_mode not in METADATA_MODE_CODES:
        raise ValueError("metadata_mode must be source-only or source-destination")
    return METADATA_MODE_CODES[metadata_mode]


def _inner_destination(packet: bytes) -> tuple[int, bytes]:
    """Validate basic inner IP framing and return (IP version, packed destination)."""
    if not isinstance(packet, bytes) or not packet:
        raise ValueError("SourceToken inner packet is empty")
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            raise ValueError("SourceToken inner IPv4 packet is too short")
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or ihl > len(packet) or int.from_bytes(packet[2:4], "big") != len(packet):
            raise ValueError("SourceToken inner IPv4 packet length invalid")
        return 4, packet[16:20]
    if version == 6:
        if len(packet) < 40 or int.from_bytes(packet[4:6], "big") + 40 != len(packet):
            raise ValueError("SourceToken inner IPv6 packet length invalid")
        return 6, packet[24:40]
    raise ValueError("SourceToken inner packet version invalid")


def _visible_destination(packet: bytes) -> bytes:
    version, address = _inner_destination(packet)
    if version == 4:
        slot = bytes(12) + address
    else:
        slot = address
    return bytes([version]) + slot


def _decode_visible_destination(value: bytes) -> tuple[int, bytes]:
    if not isinstance(value, bytes) or len(value) != VISIBLE_DESTINATION_BYTES:
        raise ValueError("SourceToken visible destination length invalid")
    version, slot = value[0], value[1:]
    if version == 4:
        if slot[:12] != bytes(12):
            raise ValueError("SourceToken visible IPv4 destination encoding invalid")
        return 4, slot[12:]
    if version == 6:
        return 6, slot
    raise ValueError("SourceToken visible destination IP version invalid")


def source_token_counter(payload: bytes, metadata_mode: str = "source-destination") -> int:
    """Read a bounded counter from a correctly framed record; does not authenticate it."""
    expected_code = _mode_code(metadata_mode)
    if not isinstance(payload, bytes) or len(payload) > MAX_UDP_PAYLOAD:
        raise ValueError("SourceToken payload length invalid")
    if len(payload) < BASE_HEADER_BYTES + MESSAGE_TYPE_BYTES + TAG_BYTES:
        raise ValueError("SourceToken payload length invalid")
    if payload[:4] != DATA_MAGIC or payload[4] != DATA_VERSION:
        raise ValueError("SourceToken data record magic or version invalid")
    mode_code = payload[5]
    if mode_code not in METADATA_CODE_MODES:
        raise ValueError("SourceToken metadata mode invalid")
    if mode_code != expected_code:
        raise ValueError("SourceToken metadata mode mismatch")
    header_length = BASE_HEADER_BYTES + (VISIBLE_DESTINATION_BYTES if mode_code == 1 else 0)
    if len(payload) < header_length + MESSAGE_TYPE_BYTES + TAG_BYTES:
        raise ValueError("SourceToken payload length invalid")
    counter = int.from_bytes(payload[6:BASE_HEADER_BYTES], "big")
    if counter >= (1 << 32):
        raise ValueError("counter must be an unsigned value below the rekey limit")
    return counter


def _nonce(iv_prefix: bytes, counter: int) -> bytes:
    if not isinstance(iv_prefix, bytes) or len(iv_prefix) != 4:
        raise ValueError("directional IV prefix must be 4 bytes")
    if type(counter) is not int or not 0 <= counter < (1 << 32):
        raise ValueError("counter must be an unsigned value below the rekey limit")
    return iv_prefix + counter.to_bytes(COUNTER_BYTES, "big")


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
    """Build a versioned NLD2 record; the complete clear header is authenticated as AAD."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("directional AES key must be 32 bytes")
    if type(message_type) is not int or message_type != 0:
        raise ValueError("only assigned message type 0 may be emitted")
    mode_code = _mode_code(metadata_mode)
    source = _outer_ipv6(outer_source, "outer_source")
    destination = _outer_ipv6(outer_destination, "outer_destination")
    if type(counter) is not int or not 0 <= counter < (1 << 32):
        raise ValueError("counter must be an unsigned value below the rekey limit")
    counter_bytes = counter.to_bytes(COUNTER_BYTES, "big")
    header = DATA_MAGIC + bytes([DATA_VERSION, mode_code]) + counter_bytes
    if mode_code == 1:
        header += _visible_destination(message_body)
    nonce = _nonce(iv_prefix, counter)
    aad = source.packed + destination.packed + header
    ciphertext = AESGCM(key).encrypt(nonce, bytes([message_type]) + message_body, aad)
    payload = header + ciphertext
    if len(payload) > MAX_UDP_PAYLOAD:
        raise ValueError("SourceToken payload exceeds maximum IPv6 UDP payload")
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
    """Authenticate/decrypt a SourceToken record; caller commits replay only after return."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("directional AES key must be 32 bytes")
    counter = source_token_counter(payload, metadata_mode)
    mode_code = _mode_code(metadata_mode)
    header_length = BASE_HEADER_BYTES + (VISIBLE_DESTINATION_BYTES if mode_code == 1 else 0)
    header = payload[:header_length]
    counter_bytes = payload[6:BASE_HEADER_BYTES]
    nonce = _nonce(iv_prefix, counter)
    source = _outer_ipv6(outer_source, "outer_source")
    destination = _outer_ipv6(outer_destination, "outer_destination")
    aad = source.packed + destination.packed + header
    try:
        plaintext = AESGCM(key).decrypt(nonce, payload[header_length:], aad)
    except InvalidTag as exc:
        raise ValueError("SourceToken authentication failed") from exc
    if not plaintext:
        raise ValueError("SourceToken plaintext is empty")
    message_type, body = plaintext[0], plaintext[1:]
    if message_type != 0:
        raise ValueError("SourceToken message type is unassigned")
    actual_destination = _inner_destination(body)
    if mode_code == 1:
        visible_destination = _decode_visible_destination(header[BASE_HEADER_BYTES:])
        if visible_destination != actual_destination:
            raise ValueError("SourceToken visible destination mismatch")
    if int.from_bytes(counter_bytes, "big") != counter:
        raise ValueError("SourceToken counter mismatch")
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
