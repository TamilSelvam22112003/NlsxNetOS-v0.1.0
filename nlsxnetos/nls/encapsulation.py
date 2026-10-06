import ipaddress
import secrets
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"NLE1"
VERSION = 1
IPV4 = 4
IPV6 = 6
# magic, version, ip_version, flags, session_id, original_destination,
# router_identity, sequence, timestamp, nonce
HEADER = struct.Struct("!4sBBB16s16s32sQQ12s")
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
    key,
    session_id,
    sequence,
    original_destination,
    router_identity,
    packet,
    timestamp=None,
):
    if len(key) != 32:
        raise ValueError("NLS key must be 32 bytes")
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")
    if len(router_identity) != 32:
        raise ValueError("router_identity must be 32 bytes")
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    inner_destination = _inner_destination(packet)
    if inner_destination != str(ipaddress.ip_address(original_destination)):
        raise ValueError("outer destination does not match inner IP destination")
    ip_version, destination = _pack_ip(original_destination)
    nonce = secrets.token_bytes(12)
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
    )
    ciphertext = AESGCM(key).encrypt(nonce, packet, header)
    return header + ciphertext


def open_ip_packet(key, packet, expected_session_id, expected_router_identity, max_clock_skew=120):
    if len(key) != 32:
        raise ValueError("NLS key must be 32 bytes")
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
    ) = HEADER.unpack(packet[:HEADER_SIZE])
    if magic != MAGIC or version != VERSION or flags != 0:
        raise ValueError("invalid NLS encapsulation header")
    if session_id != expected_session_id:
        raise ValueError("NLS session binding mismatch")
    if router_identity != expected_router_identity:
        raise ValueError("NLS router identity mismatch")
    if abs(int(time.time()) - timestamp) > max_clock_skew:
        raise ValueError("NLS packet timestamp outside allowed clock skew")
    destination_ip = _unpack_ip(ip_version, destination)
    plaintext = AESGCM(key).decrypt(nonce, packet[HEADER_SIZE:], packet[:HEADER_SIZE])
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
