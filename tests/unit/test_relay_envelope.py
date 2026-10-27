import ipaddress

import pytest

from nls.relay_envelope import (
    RelayEnvelopeError,
    open_relay_layer,
    seal_relay_layer,
)

KEY_A = bytes.fromhex("11" * 32)
KEY_B = bytes.fromhex("22" * 32)
TOKEN_A = bytes.fromhex("aa" * 16)
TOKEN_B = bytes.fromhex("bb" * 16)
INNER = b"NLR1-next-layer-payload-opaque"


def test_ipv6_relay_layer_round_trip_and_no_cleartext_locator():
    original_client = "2001:db8:abcd:10::1234"
    original_server = "2001:db8:beef:20::80"
    payload_canary = b"nls-inner-payload-secret-unique-7c89"
    inner = original_client.encode() + b"|" + original_server.encode() + b"|" + payload_canary
    packet = seal_relay_layer(KEY_A, TOKEN_A, 7, "2001:db8:1::2", 4789, inner, previous_hop_source_locator="2001:db8:1::1")
    assert b"NLR1" == packet[:4]
    assert original_client.encode() not in packet
    assert original_server.encode() not in packet
    assert payload_canary not in packet
    assert ipaddress.ip_address("2001:db8:1::2").packed not in packet
    assert ipaddress.ip_address("2001:db8:1::1").packed not in packet

    layer = open_relay_layer(KEY_A, packet, expected_hop_token=TOKEN_A, expected_sequence=7)
    assert layer.next_hop_address == "2001:db8:1::2"
    assert layer.next_hop_port == 4789
    assert layer.previous_hop_source_locator == "2001:db8:1::1"
    assert layer.inner_envelope == inner
    assert layer.sequence == 7


def test_ipv4_relay_layer_round_trip():
    packet = seal_relay_layer(KEY_A, TOKEN_A, 0, "192.0.2.10", 40000, b"inner", previous_hop_source_locator="192.0.2.9")
    layer = open_relay_layer(KEY_A, packet, expected_hop_token=TOKEN_A)
    assert layer.next_hop_address == "192.0.2.10"
    assert layer.next_hop_port == 40000
    assert layer.previous_hop_source_locator == "192.0.2.9"
    assert layer.inner_envelope == b"inner"


@pytest.mark.parametrize("mutation", ["ciphertext", "header"])
def test_tampering_is_rejected(mutation):
    packet = bytearray(seal_relay_layer(KEY_A, TOKEN_A, 3, "2001:db8::2", 4789, b"secret", previous_hop_source_locator="2001:db8::1"))
    if mutation == "ciphertext":
        packet[-1] ^= 1
    else:
        packet[6] ^= 1
    with pytest.raises(RelayEnvelopeError):
        open_relay_layer(KEY_A, bytes(packet), expected_hop_token=TOKEN_A)


def test_wrong_key_and_wrong_hop_token_fail_closed():
    packet = seal_relay_layer(KEY_A, TOKEN_A, 1, "2001:db8::2", 4789, b"secret", previous_hop_source_locator="2001:db8::1")
    with pytest.raises(RelayEnvelopeError, match="token mismatch"):
        open_relay_layer(KEY_A, packet, expected_hop_token=TOKEN_B)
    with pytest.raises(RelayEnvelopeError, match="authentication failed"):
        open_relay_layer(KEY_B, packet, expected_hop_token=TOKEN_A)


def test_wrong_sequence_is_rejected():
    packet = seal_relay_layer(KEY_A, TOKEN_A, 1, "2001:db8::2", 4789, b"secret")
    with pytest.raises(RelayEnvelopeError, match="sequence mismatch"):
        open_relay_layer(KEY_A, packet, expected_hop_token=TOKEN_A, expected_sequence=2)


@pytest.mark.parametrize(
    "address,port",
    [
        ("0.0.0.0", 4789),
        ("224.0.0.1", 4789),
        ("ff02::1", 4789),
        ("2001:db8::1", 0),
        ("2001:db8::1", 65536),
    ],
)
def test_invalid_next_hop_rejected(address, port):
    with pytest.raises(RelayEnvelopeError):
        seal_relay_layer(KEY_A, TOKEN_A, 1, address, port, b"inner", previous_hop_source_locator="2001:db8::1")


def test_truncated_and_trailing_data_rejected():
    packet = seal_relay_layer(KEY_A, TOKEN_A, 1, "2001:db8::2", 4789, b"inner", previous_hop_source_locator="2001:db8::1")
    with pytest.raises(RelayEnvelopeError):
        open_relay_layer(KEY_A, packet[:-1], expected_hop_token=TOKEN_A)
    with pytest.raises(RelayEnvelopeError, match="length mismatch"):
        open_relay_layer(KEY_A, packet + b"trailing", expected_hop_token=TOKEN_A)


def test_invalid_key_token_sequence_nonce_and_inner_types_rejected():
    with pytest.raises(RelayEnvelopeError, match="key"):
        seal_relay_layer(b"short", TOKEN_A, 1, "2001:db8::2", 4789, b"inner", previous_hop_source_locator="2001:db8::1")
    with pytest.raises(RelayEnvelopeError, match="token"):
        seal_relay_layer(KEY_A, b"short", 1, "2001:db8::2", 4789, b"inner", previous_hop_source_locator="2001:db8::1")
    with pytest.raises(RelayEnvelopeError, match="sequence"):
        seal_relay_layer(KEY_A, TOKEN_A, -1, "2001:db8::2", 4789, b"inner", previous_hop_source_locator="2001:db8::1")
    with pytest.raises(RelayEnvelopeError, match="nonce"):
        seal_relay_layer(KEY_A, TOKEN_A, 1, "2001:db8::2", 4789, b"inner", previous_hop_source_locator="2001:db8::1", nonce=b"short")
    with pytest.raises(RelayEnvelopeError, match="inner envelope"):
        seal_relay_layer(KEY_A, TOKEN_A, 1, "2001:db8::2", 4789, "not bytes", previous_hop_source_locator="2001:db8::1")
