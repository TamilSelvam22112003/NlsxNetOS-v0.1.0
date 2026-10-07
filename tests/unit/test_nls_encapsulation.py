import ipaddress

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from nlsxnetos.nls.encapsulation import HEADER, HEADER_SIZE, open_ip_packet, seal_ip_packet
from nlsxnetos.nls.rsa import public_key_b64
from nlsxnetos.nls.rsa_signing import public_key_b64 as signing_public_key_b64


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
def keys():
    encryption_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return encryption_private, signing_private


def seal(encryption_private, signing_private, payload, destination="203.0.113.10"):
    return seal_ip_packet(
        public_key_b64(encryption_private),
        encryption_private,
        signing_private,
        bytes(16),
        1,
        destination,
        bytes(range(32)),
        payload,
    )


def test_source_address_and_payload_are_encrypted(keys):
    encryption_private, signing_private = keys
    outer = seal(encryption_private, signing_private, ipv4_packet())
    fields = HEADER.unpack(outer[:HEADER_SIZE])
    assert fields[5] == ipaddress.IPv4Address("203.0.113.10").packed + bytes(12)
    assert fields[6] == bytes(range(32))
    decoded = open_ip_packet(
        encryption_private,
        outer,
        bytes(16),
        bytes(range(32)),
        signing_public_key_b64(signing_private),
    )
    assert decoded["payload"] == ipv4_packet()


def test_ipv6_destination_remains_visible_and_inner_packet_is_restored(keys):
    encryption_private, signing_private = keys
    original = ipv6_packet()
    outer = seal(encryption_private, signing_private, original, "2001:db8:2::10")
    assert ipaddress.IPv6Address("2001:db8:2::10").packed in outer[:HEADER_SIZE]
    decoded = open_ip_packet(
        encryption_private,
        outer,
        bytes(16),
        bytes(range(32)),
        signing_public_key_b64(signing_private),
    )
    assert decoded["payload"] == original


def test_inner_and_outer_destination_must_match(keys):
    encryption_private, signing_private = keys
    with pytest.raises(ValueError, match="destination"):
        seal_ip_packet(
            public_key_b64(encryption_private),
            encryption_private,
            signing_private,
            bytes(16),
            1,
            "203.0.113.20",
            bytes(range(32)),
            ipv4_packet(),
        )


def test_tampering_with_visible_header_is_rejected(keys):
    encryption_private, signing_private = keys
    outer = bytearray(seal(encryption_private, signing_private, ipv4_packet()))
    outer[25] ^= 1
    with pytest.raises(ValueError):
        open_ip_packet(
            encryption_private, bytes(outer), bytes(16), bytes(range(32)),
            signing_public_key_b64(signing_private),
        )


def test_wrong_rsa_private_key_cannot_open_packet(keys):
    encryption_private, signing_private = keys
    wrong_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    packet = seal(encryption_private, signing_private, ipv4_packet())
    with pytest.raises(Exception):
        open_ip_packet(
            wrong_private, packet, bytes(16), bytes(range(32)),
            signing_public_key_b64(signing_private),
        )


def test_wrong_signing_key_cannot_authenticate_packet(keys):
    encryption_private, signing_private = keys
    wrong_signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    packet = seal(encryption_private, signing_private, ipv4_packet())
    with pytest.raises(Exception):
        open_ip_packet(
            encryption_private, packet, bytes(16), bytes(range(32)),
            signing_public_key_b64(wrong_signing),
        )


def test_plaintext_does_not_contain_original_payload(keys):
    encryption_private, signing_private = keys
    packet = seal(encryption_private, signing_private, ipv4_packet())
    assert b"tcp-payload" not in packet
