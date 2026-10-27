import ipaddress
import struct
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives import serialization

from nls.endpoint_envelope import (
    EndpointEnvelopeError,
    open_endpoint_packet,
    seal_endpoint_packet,
)

SESSION = bytes.fromhex("12" * 16)


def ipv6_packet(destination="2001:db8:ffff::80"):
    source = ipaddress.IPv6Address("2001:db8:abcd::10").packed
    dest = ipaddress.IPv6Address(destination).packed
    return struct.pack("!IHBB16s16s", 6 << 28, 0, 17, 64, source, dest) + b"encrypted-app-payload-canary"


def keys():
    source = Ed25519PrivateKey.generate()
    dest = generate_private_key(public_exponent=65537, key_size=3072)
    return source, dest


def test_endpoint_round_trip_and_cleartext_privacy():
    source, dest = keys()
    payload = ipv6_packet()
    pub = dest.public_key()
    packet = seal_endpoint_packet(pub, source, SESSION, 5, "2001:db8:ffff::80", payload)
    assert b"encrypted-app-payload-canary" not in packet
    assert ipaddress.ip_address("2001:db8:abcd::10").packed not in packet
    assert ipaddress.ip_address("2001:db8:ffff::80").packed not in packet
    result = open_endpoint_packet(dest, source.public_key(), packet, expected_destination="2001:db8:ffff::80", expected_session_id=SESSION)
    assert result["payload"] == payload
    assert result["sequence"] == 5


def test_endpoint_tampering_is_rejected():
    source, dest = keys()
    pub = dest.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    packet = bytearray(seal_endpoint_packet(pub, source, SESSION, 1, "2001:db8:ffff::80", ipv6_packet()))
    packet[-65] ^= 1
    with pytest.raises(EndpointEnvelopeError, match="signature"):
        open_endpoint_packet(dest, source.public_key(), bytes(packet), expected_destination="2001:db8:ffff::80")


def test_endpoint_wrong_origin_key_is_rejected():
    source, dest = keys()
    other = Ed25519PrivateKey.generate()
    pub = dest.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    packet = seal_endpoint_packet(pub, source, SESSION, 1, "2001:db8:ffff::80", ipv6_packet())
    with pytest.raises(EndpointEnvelopeError, match="trusted Router-CA"):
        open_endpoint_packet(dest, other.public_key(), packet)


def test_endpoint_wrong_destination_and_expired_timestamp_rejected():
    source, dest = keys()
    pub = dest.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    packet = seal_endpoint_packet(pub, source, SESSION, 1, "2001:db8:ffff::80", ipv6_packet(), timestamp=int(time.time()) - 1000)
    with pytest.raises(EndpointEnvelopeError, match="timestamp"):
        open_endpoint_packet(dest, source.public_key(), packet)
    fresh = seal_endpoint_packet(pub, source, SESSION, 2, "2001:db8:ffff::80", ipv6_packet())
    with pytest.raises(EndpointEnvelopeError, match="inner/outer endpoint destination"):
        open_endpoint_packet(dest, source.public_key(), fresh, expected_destination="2001:db8:ffff::81")
