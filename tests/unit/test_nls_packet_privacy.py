import ipaddress

from cryptography.hazmat.primitives.asymmetric import rsa

from nls.encapsulation import HEADER, HEADER_SIZE, open_ip_packet, seal_ip_packet
from nls.rsa import public_key_b64


def ipv6_packet(source="fd42:200::10", destination="fd42:300::20"):
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = (len(b"private-nls-payload")).to_bytes(2, "big")
    header[6] = 17
    header[7] = 64
    header[8:24] = ipaddress.IPv6Address(source).packed
    header[24:40] = ipaddress.IPv6Address(destination).packed
    return bytes(header) + b"private-nls-payload"


def test_ipv6_source_and_payload_are_hidden_and_destination_is_visible():
    destination_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    destination_public = public_key_b64(destination_private)
    session_id = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
    router_identity = bytes(range(32))
    source_ip = ipaddress.IPv6Address("fd42:200::10")
    destination_ip = ipaddress.IPv6Address("fd42:300::20")
    original = ipv6_packet()

    wire = seal_ip_packet(
        destination_public,
        session_id,
        1,
        str(destination_ip),
        router_identity,
        original,
    )

    header = HEADER.unpack(wire[:HEADER_SIZE])
    assert header[5] == destination_ip.packed
    assert source_ip.packed not in wire[:HEADER_SIZE]
    assert b"private-nls-payload" not in wire

    decoded = open_ip_packet(destination_private, wire, session_id, router_identity)
    assert decoded["destination_ip"] == str(destination_ip)
    assert decoded["payload"] == original

    wrong_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    try:
        open_ip_packet(wrong_private, wire, session_id, router_identity)
    except Exception:
        pass
    else:
        raise AssertionError("packet decrypted with a non-destination private key")
