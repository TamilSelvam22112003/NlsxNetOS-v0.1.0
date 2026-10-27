import ipaddress
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from nls.endpoint_agent import EndpointAgentProcessor
from nls.endpoint_envelope import EndpointEnvelopeError, seal_endpoint_packet


SESSION = bytes.fromhex("a1" * 16)


def ipv6_packet(destination="2001:db8:ffff::80"):
    source = ipaddress.IPv6Address("2001:db8:abcd::10").packed
    dest = ipaddress.IPv6Address(destination).packed
    return struct.pack("!IHBB16s16s", 6 << 28, 0, 17, 64, source, dest) + b"application-payload"


def test_endpoint_agent_decrypts_only_with_server_private_key():
    source = Ed25519PrivateKey.generate()
    server = generate_private_key(public_exponent=65537, key_size=3072)
    packet = seal_endpoint_packet(server.public_key(), source, SESSION, 3, "2001:db8:ffff::80", ipv6_packet())
    processor = EndpointAgentProcessor(server, {source.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
    ): source.public_key()})
    assert processor.process(packet, "2001:db8:ffff::80") == ipv6_packet()


def test_endpoint_agent_rejects_untrusted_source_and_replay():
    source = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    server = generate_private_key(public_exponent=65537, key_size=3072)
    packet = seal_endpoint_packet(server.public_key(), source, SESSION, 3, "2001:db8:ffff::80", ipv6_packet())
    source_raw = source.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
    )
    processor = EndpointAgentProcessor(server, {source_raw: source.public_key()})
    with pytest.raises(EndpointEnvelopeError, match="replay"):
        processor.process(packet, "2001:db8:ffff::81")
    assert processor.process(packet, "2001:db8:ffff::80") == ipv6_packet()
    with pytest.raises(EndpointEnvelopeError, match="replay"):
        processor.process(packet, "2001:db8:ffff::80")
