"""Regression tests for the Stage 7 primary-WAN-locator contract.

These tests cover endpoint selection and normalization only. They do not replace
packet-capture or target-network destination validation.
"""
import pytest

from nls.v2_runtime import _endpoint_from_record, _normalized_endpoint


def test_rdr_primary_wan_endpoint_is_the_first_advertised_endpoint():
    record = {
        "wan_endpoints": [
            "[2001:0db8:0:0::1]:49152",
            "[2001:db8::2]:49153",
        ]
    }

    assert _endpoint_from_record(record) == "[2001:0db8:0:0::1]:49152"
    assert _normalized_endpoint(_endpoint_from_record(record)) == ("2001:db8::1", 49152)


def test_rdr_primary_endpoint_does_not_fall_back_to_secondary_endpoint():
    record = {"wan_endpoints": ["invalid", "[2001:db8::2]:49153"]}

    with pytest.raises(ValueError):
        _normalized_endpoint(_endpoint_from_record(record))


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"wan_endpoints": []},
        {"wan_endpoints": None},
        {"wan_endpoints": ["[2001:db8::1]:443", 1234]},
    ],
)
def test_rdr_requires_a_nonempty_string_endpoint_list(record):
    with pytest.raises(ValueError):
        _endpoint_from_record(record)


@pytest.mark.parametrize(
    "endpoint",
    [
        "2001:db8::1:443",
        "[2001:db8::1]",
        "[2001:db8::1]:0",
        "[2001:db8::1]:65536",
        "[not-an-ipv6-address]:443",
        "192.0.2.1:443:extra",
    ],
)
def test_invalid_or_ambiguous_primary_locator_is_rejected(endpoint):
    with pytest.raises(ValueError):
        _normalized_endpoint(endpoint)


def test_ipv4_locator_is_normalized_and_port_preserved():
    assert _normalized_endpoint("192.0.2.10:4242") == ("192.0.2.10", 4242)
