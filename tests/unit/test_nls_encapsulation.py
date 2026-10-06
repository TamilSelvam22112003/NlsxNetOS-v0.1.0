import ipaddress

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nlsxnetos.nls.encapsulation import HEADER, HEADER_SIZE, open_ip_packet, seal_ip_packet


def ipv4_packet(source="10.0.0.10", destination="203.0.113.10"):
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = (20).to_bytes(2, "big")
    header[8] = 64
    header[9] = 6
    header[12:16] = ipaddress.IPv4Address(source).packed
    header[16:20] = ipaddress.IPv4Address(destination).packed
    return bytes(header) + b"tcp-payload"


def ipv6_packet(source="2001:db8:1::10", destination="2001:db8:2::10"):
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = (8).to_bytes(2, "big")
    header[6] = 17
    header[7] = 64
    header[8:24] = ipaddress.IPv6Address(source).packed
    header[24:40] = ipaddress.IPv6Address(destination).packed
    return bytes(header) + b"udp-data"


def test_source_address_and_payload_are_encrypted():
    key = bytes(range(32))
    sid = bytes.fromhex("00112233445566778899aabbccddeeff")
    identity = bytes(range(32, 64))
    original = ipv4_packet()
    outer = seal_ip_packet(key, sid, 7, "203.0.113.10", identity, original)
    assert outer[:4] == b"NLE1"
    fields = HEADER.unpack(outer[:HEADER_SIZE])
    assert fields[5] == ipaddress.IPv4Address("203.0.113.10").packed + bytes(12)
    assert fields[6] == identity
    assert ipaddress.IPv4Address(original[12:16]).packed not in outer[:HEADER_SIZE]
    decoded = open_ip_packet(key, outer, sid, identity)
    assert decoded["destination_ip"] == "203.0.113.10"
    assert decoded["payload"] == original


def test_ipv6_destination_remains_visible_and_inner_packet_is_restored():
    key = AESGCM.generate_key(bit_length=256)
    sid = bytes(16)
    identity = bytes([7]) * 32
    original = ipv6_packet()
    outer = seal_ip_packet(key, sid, 1, "2001:db8:2::10", identity, original)
    assert ipaddress.IPv6Address("2001:db8:2::10").packed in outer[:HEADER_SIZE]
    decoded = open_ip_packet(key, outer, sid, identity)
    assert decoded["payload"] == original


def test_inner_and_outer_destination_must_match():
    key = bytes(range(32))
    sid = bytes(16)
    identity = bytes([3]) * 32
    with pytest.raises(ValueError, match="destination"):
        seal_ip_packet(key, sid, 1, "203.0.113.20", identity, ipv4_packet())


def test_tampering_with_visible_header_is_rejected():
    key = bytes(range(32))
    sid = bytes(16)
    identity = bytes([4]) * 32
    outer = bytearray(seal_ip_packet(key, sid, 1, "203.0.113.10", identity, ipv4_packet()))
    outer[25] ^= 0x01
    with pytest.raises(Exception):
        open_ip_packet(key, bytes(outer), sid, identity)
