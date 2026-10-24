"""Regression tests for hop-by-hop source-IP and inner-header confidentiality.

These tests exercise the SourceToken transport used by NLSDaemon, not merely
the standalone NLE2 helper. Each router pair gets directional keys and
direction-specific outer source tokens; the original inner IP packet must be
recoverable only by the peer holding the matching directional key.
"""
import ipaddress
import os

from nls.source_token import (
    derive_source_token,
    open_source_token_payload,
    seal_source_token_payload,
)


def _ipv6_packet(source: str, destination: str, payload: bytes) -> bytes:
    packet = bytearray(40)
    packet[0] = 0x60
    packet[4:6] = len(payload).to_bytes(2, "big")
    packet[6] = 17  # UDP
    packet[7] = 64
    packet[8:24] = ipaddress.IPv6Address(source).packed
    packet[24:40] = ipaddress.IPv6Address(destination).packed
    return bytes(packet) + payload


def _round_trip(secret, salt, sender, peer, direction, key, iv_prefix, counter, packet):
    token = derive_source_token(
        secret, salt, sender, peer, "fd00::dead", direction
    )
    peer_token = derive_source_token(
        secret, salt, sender, peer, "fd00::dead", direction
    )
    assert token == peer_token
    assert token not in (ipaddress.IPv6Address(sender), ipaddress.IPv6Address(peer))

    # The outer IPv6 source is a session/direction-specific token, not originalIP.
    wire = seal_source_token_payload(
        key, iv_prefix, counter, str(token), peer, packet
    )
    assert ipaddress.IPv6Address(sender).packed not in wire
    assert ipaddress.IPv6Address(peer).packed not in wire
    decoded_counter, message_type, plaintext = open_source_token_payload(
        key, iv_prefix, wire, str(token), peer
    )
    assert decoded_counter == counter
    assert message_type == 0
    assert plaintext == packet
    return str(token), wire


def test_request_and_response_hide_inner_source_and_destination_per_hop():
    # In a real session, this secret is the authenticated X25519 shared secret;
    # directional AES-GCM keys and IV prefixes are derived from the handshake.
    secret = os.urandom(32)
    salt = os.urandom(32)
    router_a = "2001:4860:abcd::1"
    router_b = "2001:4860:abcd::2"
    client = "2001:4860:100::10"
    server = "2001:4860:200::20"
    key_ab, key_ba = os.urandom(32), os.urandom(32)
    iv_ab, iv_ba = os.urandom(4), os.urandom(4)

    request = _ipv6_packet(client, server, b"request")
    response = _ipv6_packet(server, client, b"response")

    token_a, wire_request = _round_trip(
        secret, salt, router_a, router_b, "A-to-B",
        key_ab, iv_ab, 1, request,
    )
    token_b, wire_response = _round_trip(
        secret, salt, router_b, router_a, "B-to-A",
        key_ba, iv_ba, 2, response,
    )

    assert token_a != router_a
    assert token_b != router_b
    assert token_a != token_b
    assert request not in wire_request
    assert response not in wire_response


def test_wrong_hop_key_cannot_recover_inner_source_ip():
    secret = os.urandom(32)
    salt = os.urandom(32)
    router_a = "2001:4860:abcd::11"
    router_b = "2001:4860:abcd::22"
    packet = _ipv6_packet("2001:4860:100::11", "2001:4860:200::22", b"private")
    token = str(derive_source_token(
        secret, salt, router_a, router_b, "fd00::dead", "A-to-B"
    ))
    key, iv_prefix = os.urandom(32), os.urandom(4)
    wire = seal_source_token_payload(key, iv_prefix, 7, token, router_b, packet)

    try:
        open_source_token_payload(os.urandom(32), iv_prefix, wire, token, router_b)
    except ValueError as exc:
        assert "authentication" in str(exc).lower()
    else:
        raise AssertionError("wrong next-hop key unexpectedly decrypted the packet")
