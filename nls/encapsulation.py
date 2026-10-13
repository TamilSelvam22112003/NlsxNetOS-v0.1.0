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
    if value.version == IPV4:
        return IPV4, value.packed + bytes(12)
    return IPV6, value.packed


def _unpack_ip(version, value):
    if version == IPV4:
        if value[4:] != bytes(12):
            raise ValueError("invalid IPv4 destination encoding")
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


def seal_ip_packet(rsa_public_key, session_id, sequence, original_destination,
                   router_identity, packet, timestamp=None):
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")
    if len(router_identity) != 32:
        raise ValueError("router_identity must be 32 bytes")
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    visible_destination = str(ipaddress.ip_address(original_destination))
    if _inner_destination(packet) != visible_destination:
        raise ValueError("outer destination does not match inner IP destination")

    public_key = load_public_key(rsa_public_key) if isinstance(rsa_public_key, str) else rsa_public_key
    data_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    wrapped_key = wrap_key(public_key, data_key)
    destination_version, destination_bytes = _pack_ip(visible_destination)
    # Destination is intentionally visible for forwarding. The original source
    # address and all transport/application payload remain in AES-GCM ciphertext.
    header = HEADER.pack(
        MAGIC, VERSION, destination_version, 0, session_id,
        destination_bytes, router_identity, int(sequence), timestamp,
        nonce, len(wrapped_key),
    )
    ciphertext = AESGCM(data_key).encrypt(nonce, packet, header)
    return header + wrapped_key + ciphertext


def visible_destination(packet):
    """Read the authenticated-on-decrypt, intentionally visible routing address."""
    if len(packet) < HEADER_SIZE:
        raise ValueError("NLS encapsulated packet is too short")
    magic, version, ip_version, flags, _sid, destination, _identity, _seq, _ts, _nonce, _wrapped = HEADER.unpack(packet[:HEADER_SIZE])
    if magic != MAGIC or version != VERSION or flags != 0:
        raise ValueError("invalid NLS encapsulation header")
    return _unpack_ip(ip_version, destination)


def open_ip_packet(rsa_private_key, packet, expected_session_id,
                   expected_router_identity, max_clock_skew=120):
    if len(expected_session_id) != 16:
        raise ValueError("expected session_id must be 16 bytes")
    if len(expected_router_identity) != 32:
        raise ValueError("expected router_identity must be 32 bytes")
    if len(packet) < HEADER_SIZE + 16:
        raise ValueError("NLS encapsulated packet is too short")
    (magic, version, ip_version, flags, session_id, destination, router_identity,
     sequence, timestamp, nonce, wrapped_key_length) = HEADER.unpack(packet[:HEADER_SIZE])
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
    plaintext = AESGCM(data_key).decrypt(nonce, packet[wrapped_end:], packet[:HEADER_SIZE])
    if _inner_destination(plaintext) != destination_ip:
        raise ValueError("visible destination does not match authenticated inner destination")
    return {
        "destination_ip": destination_ip,
        "sequence": sequence,
        "timestamp": timestamp,
        "router_identity": router_identity,
        "session_id": session_id,
        "payload": plaintext,
    }


def seal_session_packet(session_key, session_id, sequence, original_destination,
                        router_identity, packet, timestamp=None):
    """Seal an inner IP packet with an authenticated session directional key."""
    if not isinstance(session_key, bytes) or len(session_key) != 32:
        raise ValueError("NLS session key must be 32 bytes")
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")
    if len(router_identity) != 32:
        raise ValueError("router_identity must be 32 bytes")
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    visible = str(ipaddress.ip_address(original_destination))
    if _inner_destination(packet) != visible:
        raise ValueError("outer destination does not match inner IP destination")
    destination_version, destination_bytes = _pack_ip(visible)
    nonce = secrets.token_bytes(12)
    header = HEADER.pack(
        MAGIC, VERSION, destination_version, 0, session_id,
        destination_bytes, router_identity, int(sequence), timestamp,
        nonce, 0,
    )
    return header + AESGCM(session_key).encrypt(nonce, packet, header)


def open_session_packet(session_key, packet, expected_session_id,
                        expected_router_identity, max_clock_skew=120):
    """Authenticate/decrypt a session packet; transit routers never call this."""
    if not isinstance(session_key, bytes) or len(session_key) != 32:
        raise ValueError("NLS session key must be 32 bytes")
    if len(packet) < HEADER_SIZE + 16:
        raise ValueError("NLS encapsulated packet is too short")
    (magic, version, ip_version, flags, session_id, destination, router_identity,
     sequence, timestamp, nonce, wrapped_key_length) = HEADER.unpack(packet[:HEADER_SIZE])
    if magic != MAGIC or version != VERSION or flags != 0:
        raise ValueError("invalid NLS encapsulation header")
    if wrapped_key_length != 0:
        raise ValueError("session packet must not contain an RSA wrapped key")
    if session_id != expected_session_id:
        raise ValueError("NLS session binding mismatch")
    if router_identity != expected_router_identity:
        raise ValueError("NLS router identity mismatch")
    if abs(int(time.time()) - timestamp) > max_clock_skew:
        raise ValueError("NLS packet timestamp outside allowed clock skew")
    destination_ip = _unpack_ip(ip_version, destination)
    plaintext = AESGCM(session_key).decrypt(nonce, packet[HEADER_SIZE:], packet[:HEADER_SIZE])
    if _inner_destination(plaintext) != destination_ip:
        raise ValueError("visible destination does not match authenticated inner destination")
    return {
        "destination_ip": destination_ip,
        "sequence": sequence,
        "timestamp": timestamp,
        "router_identity": router_identity,
        "session_id": session_id,
        "payload": plaintext,
    }
