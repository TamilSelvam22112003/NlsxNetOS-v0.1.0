import ipaddress

import pytest

from nls.source_token import (
    POLICY_V1_EXCLUSIONS,
    SOURCE_TOKEN_ATTEMPTS,
    address_policy_valid,
    derive_source_token,
    open_source_token_payload,
    seal_source_token_payload,
    source_token_counter,
    validate_original_ip,
)


SECRET = bytes(range(32))
SALT = bytes(range(32, 64))
A = "2001:4860:4860::8888"
B = "2606:4700:4700::1111"
VIP = "fd42:4e4c:53::1234"


def test_source_token_is_deterministic_and_policy_valid():
    first = derive_source_token(SECRET, SALT, A, B, VIP, "A-to-B")
    second = derive_source_token(SECRET, SALT, A, B, VIP, "A-to-B")
    assert first == second
    assert address_policy_valid(first)
    assert first not in (ipaddress.IPv6Address(A), ipaddress.IPv6Address(B), ipaddress.IPv6Address(VIP))


def test_source_token_direction_is_separated():
    ab = derive_source_token(SECRET, SALT, A, B, VIP, "A-to-B")
    ba = derive_source_token(SECRET, SALT, B, A, VIP, "B-to-A")
    assert ab != ba


@pytest.mark.parametrize("address", [
    "1fff:ffff:ffff:ffff::1",
    "4000::1",
])
def test_address_policy_rejects_outside_global_unicast_and_exclusions(address):
    assert not address_policy_valid(address)


@pytest.mark.parametrize("network", POLICY_V1_EXCLUSIONS)
def test_every_pinned_exclusion_is_rejected(network):
    assert not address_policy_valid(network.network_address)


@pytest.mark.parametrize("address", [
    "2001:4860:4860::8888",
    "2606:4700:4700::1111",
    "2404:6800:4000::1",
])
def test_valid_global_unicast_samples_are_accepted(address):
    assert address_policy_valid(address)


def test_unknown_policy_version_fails_closed():
    with pytest.raises(ValueError, match="unsupported IPv6 address policy version"):
        address_policy_valid("2001:4860:4860::8888", 2)


@pytest.mark.parametrize("direction", ["bad", "", "A-to-C"])
def test_unknown_direction_fails_closed(direction):
    with pytest.raises(ValueError, match="direction"):
        derive_source_token(SECRET, SALT, A, B, VIP, direction)


def test_same_router_original_ip_fails_closed():
    with pytest.raises(ValueError, match="must differ"):
        derive_source_token(SECRET, SALT, A, A, VIP, "A-to-B")


def test_attempt_limit_is_exactly_256():
    assert SOURCE_TOKEN_ATTEMPTS == 256


def _ipv6_packet():
    packet = bytearray(40)
    packet[0] = 0x60
    packet[4:6] = (0).to_bytes(2, "big")
    packet[6] = 59
    packet[7] = 64
    packet[8:24] = ipaddress.IPv6Address("2001:db8:1::1").packed
    packet[24:40] = ipaddress.IPv6Address("2001:db8:2::2").packed
    return bytes(packet)


def test_source_token_payload_round_trip_and_counter_layout():
    key = bytes(range(32))
    prefix = b"iv01"
    source = "2001:4860:4860::1234"
    destination = "2606:4700:4700::1234"
    packet = _ipv6_packet()
    payload = seal_source_token_payload(key, prefix, 7, source, destination, packet)
    assert payload[:4] == b"NLD2"
    assert payload[4] == 2
    assert payload[5] == 2
    assert payload[6:14] == (7).to_bytes(8, "big")
    assert source_token_counter(payload) == 7
    counter, message_type, opened = open_source_token_payload(
        key, prefix, payload, source, destination
    )
    assert (counter, message_type, opened) == (7, 0, packet)


@pytest.mark.parametrize("source,destination,counter_change", [
    ("2001:4860:4860::1235", "2606:4700:4700::1234", False),
    ("2001:4860:4860::1234", "2606:4700:4700::1235", False),
])
def test_outer_address_changes_fail_aead(source, destination, counter_change):
    key = bytes(range(32))
    payload = seal_source_token_payload(
        key, b"iv01", 7, "2001:4860:4860::1234", "2606:4700:4700::1234", _ipv6_packet()
    )
    with pytest.raises(ValueError, match="authentication"):
        open_source_token_payload(key, b"iv01", payload, source, destination)


def test_counter_tampering_fails_aead():
    key = bytes(range(32))
    payload = bytearray(seal_source_token_payload(
        key, b"iv01", 7, "2001:4860:4860::1234", "2606:4700:4700::1234", _ipv6_packet()
    ))
    payload[13] ^= 1
    with pytest.raises(ValueError, match="authentication"):
        open_source_token_payload(
            key, b"iv01", bytes(payload), "2001:4860:4860::1234", "2606:4700:4700::1234"
        )


def test_sender_cannot_emit_unassigned_message_type():
    with pytest.raises(ValueError, match="only assigned message type 0"):
        seal_source_token_payload(
            bytes(range(32)), b"iv01", 0, "2001:4860::1", "2606:4700::1",
            _ipv6_packet(), message_type=1
        )


@pytest.mark.parametrize("address", ["::", "::1", "ff02::1", "fe80::1", "::ffff:192.0.2.1"])
def test_original_ip_special_addresses_are_rejected(address):
    with pytest.raises(ValueError, match="originalIP"):
        validate_original_ip(address)


def test_source_token_retries_collision_with_original_ip(monkeypatch):
    import nls.source_token as source_token

    candidates = iter([
        ipaddress.IPv6Address(A),
        ipaddress.IPv6Address("2001:db8::1"),
        ipaddress.IPv6Address("2001:4860:4860::abcd"),
    ])
    monkeypatch.setattr(source_token, "_candidate",
                        lambda *_args: next(candidates))
    token = derive_source_token(SECRET, SALT, A, B, VIP, "A-to-B")
    assert token == ipaddress.IPv6Address("2001:4860:4860::abcd")


def test_source_token_exhaustion_fails_closed(monkeypatch):
    import nls.source_token as source_token

    monkeypatch.setattr(source_token, "_candidate",
                        lambda *_args: ipaddress.IPv6Address("2001:db8::1"))
    with pytest.raises(ValueError, match="exhausted attempts"):
        derive_source_token(SECRET, SALT, A, B, VIP, "A-to-B")


def _ipv4_packet(destination="192.0.2.20"):
    packet = bytearray(20)
    packet[0] = 0x45
    packet[2:4] = (20).to_bytes(2, "big")
    packet[8] = 64
    packet[9] = 1
    packet[12:16] = ipaddress.IPv4Address("192.0.2.10").packed
    packet[16:20] = ipaddress.IPv4Address(destination).packed
    return bytes(packet)


def test_source_only_mode_exposes_authenticated_ipv6_destination():
    key = bytes(range(32))
    prefix = b"iv01"
    source = "2001:4860:4860::1234"
    destination = "2606:4700:4700::1234"
    packet = _ipv6_packet()
    payload = seal_source_token_payload(
        key, prefix, 7, source, destination, packet, metadata_mode="source-only"
    )
    assert payload[:4] == b"NLD2"
    assert payload[5] == 1
    assert payload[14] == 6
    assert payload[15:31] == ipaddress.IPv6Address("2001:db8:2::2").packed
    assert open_source_token_payload(
        key, prefix, payload, source, destination, metadata_mode="source-only"
    ) == (7, 0, packet)


def test_source_only_mode_encodes_ipv4_destination_unambiguously():
    key = bytes(range(32))
    prefix = b"iv01"
    source = "2001:4860:4860::1234"
    destination = "2606:4700:4700::1234"
    packet = _ipv4_packet()
    payload = seal_source_token_payload(
        key, prefix, 3, source, destination, packet, metadata_mode="source-only"
    )
    assert payload[14] == 4
    assert payload[15:27] == bytes(12)
    assert payload[27:31] == ipaddress.IPv4Address("192.0.2.20").packed
    assert open_source_token_payload(
        key, prefix, payload, source, destination, metadata_mode="source-only"
    ) == (3, 0, packet)


def test_metadata_mode_mismatch_fails_closed():
    key = bytes(range(32))
    payload = seal_source_token_payload(
        key, b"iv01", 0, "2001:4860::1", "2606:4700::1",
        _ipv6_packet(), metadata_mode="source-only"
    )
    with pytest.raises(ValueError, match="metadata mode mismatch"):
        open_source_token_payload(
            key, b"iv01", payload, "2001:4860::1", "2606:4700::1",
            metadata_mode="source-destination"
        )


@pytest.mark.parametrize(("offset", "value", "message"), [
    (4, 3, "magic or version"),
    (5, 99, "metadata mode invalid"),
])
def test_unknown_data_record_version_or_mode_fails_closed(offset, value, message):
    key = bytes(range(32))
    payload = bytearray(seal_source_token_payload(
        key, b"iv01", 0, "2001:4860::1", "2606:4700::1", _ipv6_packet()
    ))
    payload[offset] = value
    with pytest.raises(ValueError, match=message):
        source_token_counter(bytes(payload))


def test_authenticated_visible_destination_must_match_inner_packet():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = bytes(range(32))
    prefix = b"iv01"
    counter = 5
    source = "2001:4860:4860::1234"
    destination = "2606:4700:4700::1234"
    packet = _ipv6_packet()
    wrong_field = bytes([6]) + ipaddress.IPv6Address("2001:db8:ffff::1").packed
    header = b"NLD2" + bytes([2, 1]) + counter.to_bytes(8, "big") + wrong_field
    aad = ipaddress.IPv6Address(source).packed + ipaddress.IPv6Address(destination).packed + header
    ciphertext = AESGCM(key).encrypt(prefix + counter.to_bytes(8, "big"), b"\x00" + packet, aad)
    with pytest.raises(ValueError, match="visible destination mismatch"):
        open_source_token_payload(
            key, prefix, header + ciphertext, source, destination, metadata_mode="source-only"
        )


def test_source_only_visible_destination_tampering_fails_aead():
    key = bytes(range(32))
    source = "2001:4860::1"
    destination = "2606:4700::1"
    payload = bytearray(seal_source_token_payload(
        key, b"iv01", 0, source, destination, _ipv6_packet(), metadata_mode="source-only"
    ))
    payload[30] ^= 1
    with pytest.raises(ValueError, match="authentication"):
        open_source_token_payload(
            key, b"iv01", bytes(payload), source, destination, metadata_mode="source-only"
        )


def test_counter_first_legacy_source_token_payload_is_rejected_without_fallback():
    key = bytes(range(32))
    legacy = (0).to_bytes(8, "big") + bytes(40)
    with pytest.raises(ValueError, match="magic or version invalid"):
        source_token_counter(legacy)
    with pytest.raises(ValueError, match="magic or version invalid"):
        open_source_token_payload(
            key, b"iv01", legacy, "2001:4860::1", "2606:4700::1"
        )


def test_source_token_counter_rejects_hard_limit_exhaustion():
    exhausted = b"NLD2" + bytes([2, 2]) + (1 << 32).to_bytes(8, "big") + bytes(17)
    with pytest.raises(ValueError, match="below the rekey limit"):
        source_token_counter(exhausted)
