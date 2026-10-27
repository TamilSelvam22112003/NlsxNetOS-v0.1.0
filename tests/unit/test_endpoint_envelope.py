import ipaddress
import struct
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from nls.endpoint_envelope import (
    EndpointEnvelopeError,
    open_endpoint_packet,
    seal_endpoint_packet,
    verify_endpoint_envelope,
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


def test_router_can_verify_endpoint_origin_without_decrypting():
    source, dest = keys()
    packet = seal_endpoint_packet(dest.public_key(), source, SESSION, 8, "2001:db8:ffff::80", ipv6_packet())
    metadata = verify_endpoint_envelope(source.public_key(), packet)
    assert metadata["source_identity"] == source.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
    )
    assert metadata["sequence"] == 8


def test_router_rejects_tampered_endpoint_before_forwarding():
    source, dest = keys()
    packet = bytearray(seal_endpoint_packet(dest.public_key(), source, SESSION, 9, "2001:db8:ffff::80", ipv6_packet()))
    packet[-1] ^= 1
    with pytest.raises(EndpointEnvelopeError, match="signature"):
        verify_endpoint_envelope(source.public_key(), bytes(packet))
