import ipaddress
import struct
import time

from .rsa import decrypt_chunks, load_public_key, encrypt_chunks, load_private_key

MAGIC = b"NLE1"
VERSION = 2
IPV4 = 4
IPV6 = 6

# RSA-only NLS data-plane header.
#
# The original IP packet is split into RSA-OAEP/SHA-256 plaintext blocks and
# each block is encrypted directly with the destination router's RSA public key.
# No symmetric data key, nonce, or AES operation is used.
HEADER = struct.Struct("!4sBBB16s16s32sQQIHH")
HEADER_SIZE = HEADER.size
MAX_CHUNKS = 255


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
    if not packet:
        raise ValueError("empty IP packet")

    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    inner_destination = _inner_destination(packet)
    if inner_destination != str(ipaddress.ip_address(original_destination)):
        raise ValueError("outer destination does not match inner IP destination")

    public_key = load_public_key(rsa_public_key) if isinstance(rsa_public_key, str) else rsa_public_key
    plaintext_block_size = public_key.key_size // 8 - 2 * 32 - 2
    chunk_count = (len(packet) + plaintext_block_size - 1) // plaintext_block_size
    if chunk_count > MAX_CHUNKS:
        raise ValueError("IP packet is too large for RSA-only NLS encapsulation")

    ciphertext_block_size = public_key.key_size // 8
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
        len(packet),
        ciphertext_block_size,
        chunk_count,
    )
    ciphertext = encrypt_chunks(public_key, packet)
    return header + ciphertext


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
    if len(packet) < HEADER_SIZE:
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
        plaintext_length,
        ciphertext_block_size,
        chunk_count,
    ) = HEADER.unpack(packet[:HEADER_SIZE])

    if magic != MAGIC or version != VERSION or flags != 0:
        raise ValueError("invalid NLS encapsulation header")
    if session_id != expected_session_id:
        raise ValueError("NLS session binding mismatch")
    if router_identity != expected_router_identity:
        raise ValueError("NLS router identity mismatch")
    if not 1 <= chunk_count <= MAX_CHUNKS:
        raise ValueError("invalid RSA chunk count")
    if ciphertext_block_size not in (256, 384, 512):
        raise ValueError("unsupported RSA ciphertext block size")
    if plaintext_length < 1:
        raise ValueError("invalid plaintext length")

    expected_ciphertext_length = ciphertext_block_size * chunk_count
    if len(packet) != HEADER_SIZE + expected_ciphertext_length:
        raise ValueError("NLS encapsulated packet length mismatch")
    if abs(int(time.time()) - timestamp) > max_clock_skew:
        raise ValueError("NLS packet timestamp outside allowed clock skew")

    private_key = load_private_key(rsa_private_key) if isinstance(rsa_private_key, str) else rsa_private_key
    if private_key.key_size // 8 != ciphertext_block_size:
        raise ValueError("RSA ciphertext block size does not match local private key")

    ciphertext = packet[HEADER_SIZE:]
    plaintext = decrypt_chunks(private_key, ciphertext, chunk_count)
    if len(plaintext) != plaintext_length:
        raise ValueError("RSA plaintext length mismatch")
    destination_ip = _unpack_ip(ip_version, destination)
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
    if len(packet) < HEADER_SIZE:
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
        plaintext_length,
        ciphertext_block_size,
        chunk_count,
    ) = HEADER.unpack(packet[:HEADER_SIZE])
    if magic != MAGIC or version != VERSION or flags != 0:
        raise ValueError("invalid NLS encapsulation header")
    if not 1 <= chunk_count <= MAX_CHUNKS:
        raise ValueError("invalid RSA chunk count")
    if ciphertext_block_size not in (256, 384, 512):
        raise ValueError("unsupported RSA ciphertext block size")
    if plaintext_length < 1:
        raise ValueError("invalid plaintext length")
    if len(packet) != HEADER_SIZE + ciphertext_block_size * chunk_count:
        raise ValueError("NLS encapsulated packet length mismatch")
    return {
        "destination_ip": _unpack_ip(ip_version, destination),
        "session_id": session_id,
        "sequence": sequence,
        "timestamp": timestamp,
        "router_identity": router_identity,
    }
