import ipaddress
import secrets
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .rsa import load_public_key, unwrap_key, wrap_key

MAGIC = b"NLE1"
VERSION = 1
IPV4 = 4
IPV6 = 6
HEADER = struct.Struct("!4sBBB16s16s32sQQ12sH")
HEADER_SIZE = HEADER.size


def _pack_ip(address):
    value = ipaddress.ip_address(address)
    if value.version == 4:
        return IPV4, value.packed + bytes(12)
    return IPV6, value.packed


def _unpack_ip(version, value):
    if version == IPV4:
        return str(ipaddress.IPv4Address(value[:4]))
    if version == IPV6:
        return str(ipaddress.IPv6Address(value))
    raise ValueError("unsupported NLS destination IP version")


def _inner_destination(packet):
    if not packet:
        raise ValueError("empty IP packet")
    version = packet[0] >> 4
    if version == IPV4:
        if len(packet) < 20:
            raise ValueError("IPv4 packet is too short")
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            raise ValueError("invalid IPv4 header")
        return str(ipaddress.IPv4Address(packet[16:20]))
    if version == IPV6:
        if len(packet) < 40:
            raise ValueError("IPv6 packet is too short")
        return str(ipaddress.IPv6Address(packet[24:40]))
    raise ValueError("unsupported IP packet version")


def seal_ip_packet(
    rsa_public_key,
    session_id,
    sequence,
    original_destination,
    router_identity,
    packet,
    timestamp=None,
):
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")
    if len(router_identity) != 32:
        raise ValueError("router_identity must be 32 bytes")
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    inner_destination = _inner_destination(packet)
    if inner_destination != str(ipaddress.ip_address(original_destination)):
        raise ValueError("outer destination does not match inner IP destination")

    public_key = load_public_key(rsa_public_key) if isinstance(rsa_public_key, str) else rsa_public_key
    data_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    wrapped_key = wrap_key(public_key, data_key)
    ip_version, destination = _pack_ip(original_destination)
    header = HEADER.pack(
        MAGIC,
        VERSION,
        ip_version,
        0,
        session_id,
        destination,
        router_identity,
        int(sequence),
        timestamp,
        nonce,
        len(wrapped_key),
    )
    ciphertext = AESGCM(data_key).encrypt(nonce, packet, header)
    return header + wrapped_key + ciphertext


def open_ip_packet(
    rsa_private_key,
    packet,
    expected_session_id,
    expected_router_identity,
    max_clock_skew=120,
):
    if len(expected_session_id) != 16:
        raise ValueError("expected session_id must be 16 bytes")
    if len(expected_router_identity) != 32:
        raise ValueError("expected router_identity must be 32 bytes")
    if len(packet) < HEADER_SIZE + 16:
        raise ValueError("NLS encapsulated packet is too short")
    (
        magic,
        version,
        ip_version,
        flags,
        session_id,
        destination,
        router_identity,
        sequence,
        timestamp,
        nonce,
        wrapped_key_length,
    ) = HEADER.unpack(packet[:HEADER_SIZE])
    if magic != MAGIC or version != VERSION or flags != 0:
        raise ValueError("invalid NLS encapsulation header")
    if session_id != expected_session_id:
        raise ValueError("NLS session binding mismatch")
    if router_identity != expected_router_identity:
        raise ValueError("NLS router identity mismatch")
    if not 256 <= wrapped_key_length <= 1024:
        raise ValueError("invalid RSA wrapped-key length")
    wrapped_end = HEADER_SIZE + wrapped_key_length
    if len(packet) < wrapped_end + 16:
        raise ValueError("NLS encapsulated packet is truncated")
    if abs(int(time.time()) - timestamp) > max_clock_skew:
        raise ValueError("NLS packet timestamp outside allowed clock skew")

    destination_ip = _unpack_ip(ip_version, destination)
    data_key = unwrap_key(rsa_private_key, packet[HEADER_SIZE:wrapped_end])
    if len(data_key) != 32:
        raise ValueError("invalid NLS data key")
    plaintext = AESGCM(data_key).decrypt(
        nonce,
        packet[wrapped_end:],
        packet[:HEADER_SIZE],
    )
    if _inner_destination(plaintext) != destination_ip:
        raise ValueError("inner/outer destination mismatch")
    return {
        "destination_ip": destination_ip,
        "sequence": sequence,
        "timestamp": timestamp,
        "router_identity": router_identity,
        "session_id": session_id,
        "payload": plaintext,
    }


def peek_ip_packet(packet):
    """Read the visible NLS forwarding destination without decrypting payload."""
    if len(packet) < HEADER_SIZE + 16:
        raise ValueError("NLS encapsulated packet is too short")
    (
        magic,
        version,
        ip_version,
        flags,
        session_id,
        destination,
        router_identity,
        sequence,
        timestamp,
        nonce,
        wrapped_key_length,
    ) = HEADER.unpack(packet[:HEADER_SIZE])
    if magic != MAGIC or version != VERSION or flags != 0:
        raise ValueError("invalid NLS encapsulation header")
    if not 256 <= wrapped_key_length <= 1024:
        raise ValueError("invalid RSA wrapped-key length")
    if len(packet) < HEADER_SIZE + wrapped_key_length + 16:
        raise ValueError("NLS encapsulated packet is truncated")
    return {
        "destination_ip": _unpack_ip(ip_version, destination),
        "session_id": session_id,
        "sequence": sequence,
        "timestamp": timestamp,
        "router_identity": router_identity,
    }
