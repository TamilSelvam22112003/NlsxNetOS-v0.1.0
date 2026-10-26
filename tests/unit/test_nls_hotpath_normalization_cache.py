import ipaddress

import pytest

from nls import source_token
from nls.daemon import NLSDaemon, _compiled_prefix_networks


def test_source_token_ipv6_text_cache_is_bounded_and_keeps_zone_rejection():
    source_token._cached_ipv6_text.cache_clear()

    first = source_token._ipv6("2001:0db8::1", "source")
    second = source_token._ipv6("2001:0db8::1", "destination")

    assert str(first) == "2001:db8::1"
    assert first is second
    info = source_token._cached_ipv6_text.cache_info()
    assert info.maxsize == 4096
    assert info.hits == 1
    assert info.currsize == 1

    with pytest.raises(ValueError, match="zone identifier"):
        source_token._ipv6("fe80::1%eth0", "outer source")
    with pytest.raises(ValueError, match="must be an IPv6 address"):
        source_token._ipv6("not::an::address", "outer source")


def test_prefix_network_cache_reuses_exact_prefix_set_and_tracks_updates():
    _compiled_prefix_networks.cache_clear()
    address = ipaddress.IPv6Address("2001:db8:1::10")
    prefixes = ["2001:db8::/32", "192.0.2.0/24", "not-a-prefix"]

    assert NLSDaemon._address_in_prefixes(address, prefixes) is True
    assert NLSDaemon._address_in_prefixes(address, prefixes) is True
    info = _compiled_prefix_networks.cache_info()
    assert info.maxsize == 1024
    assert info.misses == 1
    assert info.hits == 1

    # An updated signed prefix list makes a different cache key and cannot
    # inherit authorization from the previous RDR prefix set.
    prefixes[0] = "2001:db9::/32"
    assert NLSDaemon._address_in_prefixes(address, prefixes) is False
    assert _compiled_prefix_networks.cache_info().misses == 2


def test_non_string_prefix_records_keep_tolerant_fallback_behavior():
    address = ipaddress.IPv6Address("2001:db8:1::10")
    prefixes = [None, ipaddress.IPv6Network("2001:db8::/32")]

    assert NLSDaemon._address_in_prefixes(address, prefixes) is True
