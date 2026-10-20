import ipaddress

import pytest

from nls.source_token import (
    POLICY_V1_EXCLUSIONS,
    SOURCE_TOKEN_ATTEMPTS,
    address_policy_valid,
    derive_source_token,
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
