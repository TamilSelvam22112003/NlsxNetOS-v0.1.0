import ipaddress
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nls.endpoint_session import (
    EndpointSessionError,
    accept_response,
    open_data,
    respond_to_init,
    seal_data,
    new_init,
)


def identity_raw(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def ipv6_packet(source, destination, payload=b"endpoint-session-canary"):
    return (
        struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(payload),
            17,
            64,
            ipaddress.IPv6Address(source).packed,
            ipaddress.IPv6Address(destination).packed,
        )
        + payload
    )


def established_sessions():
    initiator_identity = Ed25519PrivateKey.generate()
    responder_identity = Ed25519PrivateKey.generate()
    initiator_raw = identity_raw(initiator_identity)
    responder_raw = identity_raw(responder_identity)
    init_packet, pending = new_init(initiator_identity, responder_raw)
    response_packet, responder = respond_to_init(
        init_packet,
        responder_identity,
        {initiator_raw: initiator_identity.public_key()},
    )
    initiator = accept_response(
        response_packet,
        pending,
        responder_identity.public_key(),
        initiator_identity,
    )
    return initiator_identity, responder_identity, initiator, responder, init_packet, pending


def test_authenticated_x25519_handshake_derives_matching_directional_keys():
    _src, _dst, initiator, responder, _init, _pending = established_sessions()
    assert initiator.session_id == responder.session_id
    assert initiator.tx_key == responder.rx_key
    assert initiator.rx_key == responder.tx_key
    assert initiator.tx_key != initiator.rx_key


def test_nle3_round_trip_hides_inner_ip_and_payload_and_supports_reverse_direction():
    _src, _dst, initiator, responder, _init, _pending = established_sessions()
    client = "2001:db8:abcd::10"
    server = "2001:db8:ffff::80"
    request = ipv6_packet(client, server)
    encrypted = seal_data(initiator, request, server)
    assert b"endpoint-session-canary" not in encrypted
    assert ipaddress.IPv6Address(client).packed not in encrypted
    assert ipaddress.IPv6Address(server).packed not in encrypted
    assert open_data(encrypted, responder, server)["payload"] == request

    reply = ipv6_packet(server, client, b"response-canary")
    encrypted_reply = seal_data(responder, reply, client)
    assert open_data(encrypted_reply, initiator, client)["payload"] == reply


def test_endpoint_handshake_rejects_unregistered_or_wrong_target_identity():
    source = Ed25519PrivateKey.generate()
    destination = Ed25519PrivateKey.generate()
    init_packet, _pending = new_init(source, identity_raw(destination))
    with pytest.raises(EndpointSessionError, match="not trusted"):
        respond_to_init(init_packet, destination, {})
    other = Ed25519PrivateKey.generate()
    with pytest.raises(EndpointSessionError, match="target identity"):
        respond_to_init(
            init_packet,
            other,
            {identity_raw(source): source.public_key()},
        )


def test_endpoint_response_is_transcript_and_identity_bound():
    source, destination, _initiator, _responder, init_packet, pending = established_sessions()
    responder2 = Ed25519PrivateKey.generate()
    response, _ = respond_to_init(
        init_packet,
        responder2,
        {identity_raw(source): source.public_key()},
    )
    with pytest.raises(EndpointSessionError, match="source identity"):
        accept_response(response, pending, responder2.public_key(), source)

    _response, pending2 = new_init(source, identity_raw(destination))
    good_response, _ = respond_to_init(
        init_packet,
        destination,
        {identity_raw(source): source.public_key()},
    )
    with pytest.raises(EndpointSessionError, match="transcript"):
        accept_response(good_response, pending2, destination.public_key(), source)


def test_nle3_tampering_replay_and_wrong_destination_are_rejected():
    _src, _dst, initiator, responder, _init, _pending = established_sessions()
    client = "2001:db8:abcd::10"
    server = "2001:db8:ffff::80"
    packet = seal_data(initiator, ipv6_packet(client, server), server)
    tampered = bytearray(packet)
    tampered[-1] ^= 1
    with pytest.raises(EndpointSessionError, match="AEAD authentication"):
        open_data(bytes(tampered), responder, server)

    with pytest.raises(EndpointSessionError, match="destination"):
        open_data(packet, responder, "2001:db8:ffff::81")

    assert open_data(packet, responder, server)["sequence"] == 0
    with pytest.raises(EndpointSessionError, match="replay"):
        open_data(packet, responder, server)
