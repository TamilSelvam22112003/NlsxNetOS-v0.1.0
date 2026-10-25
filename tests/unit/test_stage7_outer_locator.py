"""Stage 7 tests for authoritative outer-locator validation."""
import pytest

from nls.v2_runtime import _assert_authoritative_outer_endpoint


def test_outer_locator_must_match_signed_primary_wan_endpoint():
    record = {"wan_endpoints": ["[2001:4860:4860::8888]:4789"]}
    _assert_authoritative_outer_endpoint(("2001:4860:4860::8888", 4789), record)


@pytest.mark.parametrize("observed", [
    ("2001:4860:4860::8844", 4789),
    ("2001:4860:4860::8888", 4790),
    ("2001:4860:4860::8888", "4789"),
])
def test_outer_locator_rejects_address_or_port_mismatch(observed):
    record = {"wan_endpoints": ["[2001:4860:4860::8888]:4789"]}
    with pytest.raises(ValueError, match="NLS_HS_OUTER_LOCATOR_MISMATCH"):
        _assert_authoritative_outer_endpoint(observed, record)


def test_outer_locator_rejects_non_ipv6_observed_source():
    record = {"wan_endpoints": ["[2001:4860:4860::8888]:4789"]}
    with pytest.raises((ValueError, TypeError)):
        _assert_authoritative_outer_endpoint(("192.0.2.1", 4789), record)
