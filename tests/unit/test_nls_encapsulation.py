import ipaddress

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from nlsxnetos.nls.encapsulation import HEADER, HEADER_SIZE, open_ip_packet, seal_ip_packet
from nlsxnetos.nls.rsa import public_key_b64


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


@pytest.fixture
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return private_key, public_key_b64(private_key)


def test_source_address_and_payload_are_encrypted(rsa_keys):
    private_key, public_key = rsa_keys
    sid = bytes.fromhex("00112233445566778899aabbccddeeff")
    identity = bytes(range(32, 64))
    original = ipv4_packet()
    outer = seal_ip_packet(public_key, private_key, sid, 7, "203.0.113.10", identity, original)
    assert outer[:4] == b"NLE1"
    fields = HEADER.unpack(outer[:HEADER_SIZE])
    assert fields[5] == ipaddress.IPv4Address("203.0.113.10").packed + bytes(12)
    assert fields[6] == identity
    assert ipaddress.IPv4Address(original[12:16]).packed not in outer[:HEADER_SIZE]
    decoded = open_ip_packet(private_key, outer, sid, identity, public_key)
    assert decoded["destination_ip"] == "203.0.113.10"
    assert decoded["payload"] == original


def test_ipv6_destination_remains_visible_and_inner_packet_is_restored(rsa_keys):
    private_key, public_key = rsa_keys
    sid = bytes(16)
    identity = bytes([7]) * 32
    original = ipv6_packet()
    outer = seal_ip_packet(public_key, private_key, sid, 1, "2001:db8:2::10", identity, original)
    assert ipaddress.IPv6Address("2001:db8:2::10").packed in outer[:HEADER_SIZE]
    decoded = open_ip_packet(private_key, outer, sid, identity)
    assert decoded["payload"] == original


def test_inner_and_outer_destination_must_match(rsa_keys):
    _, public_key = rsa_keys
    sid = bytes(16)
    identity = bytes([3]) * 32
    with pytest.raises(ValueError, match="destination"):
        seal_ip_packet(public_key, private_key, sid, 1, "203.0.113.20", identity, ipv4_packet())


def test_tampering_with_visible_header_is_rejected(rsa_keys):
    private_key, public_key = rsa_keys
    sid = bytes(16)
    identity = bytes([4]) * 32
    outer = bytearray(seal_ip_packet(public_key, private_key, sid, 1, "203.0.113.10", identity, ipv4_packet()))
    outer[25] ^= 0x01
    with pytest.raises(Exception):
        open_ip_packet(private_key, bytes(outer), sid, identity)


def test_wrong_rsa_private_key_cannot_open_packet(rsa_keys):
    _, public_key = rsa_keys
    wrong_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    sid = bytes(16)
    identity = bytes([5]) * 32
    packet = seal_ip_packet(public_key, sid, 1, "203.0.113.10", identity, ipv4_packet())
    with pytest.raises(Exception):
        open_ip_packet(wrong_private, packet, sid, identity, public_key)


def test_plaintext_does_not_contain_original_payload(rsa_keys):
    _, public_key = rsa_keys
    sid = bytes(16)
    identity = bytes([6]) * 32
    packet = seal_ip_packet(public_key, sid, 1, "203.0.113.10", identity, ipv4_packet())
    assert b"tcp-payload" not in packet
