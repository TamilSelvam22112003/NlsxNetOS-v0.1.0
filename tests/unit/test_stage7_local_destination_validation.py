"""Tests for fail-closed Stage 7 local destination-locator validation."""
import ipaddress
import socket
import threading
from types import SimpleNamespace

import pytest

from nls.daemon import NLSDaemon
from nls.v2_runtime import HandshakeV2, _local_endpoint_matches


@pytest.mark.parametrize(
    ("expected", "observed", "matches"),
    [
        ("[2001:db8::1]:49152", ("2001:0db8:0:0::1", 49152), True),
        ("[2001:db8::1]:49152", ("2001:db8::2", 49152), False),
        ("[2001:db8::1]:49152", ("2001:db8::1", 49153), False),
        ("192.0.2.10:4242", ("192.0.2.10", 4242), True),
        ("192.0.2.10:4242", ("192.0.2.11", 4242), False),
        ("192.0.2.10:4242", None, False),
        ("192.0.2.10:4242", ("not-an-ip", 4242), False),
        ("192.0.2.10:4242", ("192.0.2.10", "bad-port"), False),
    ],
)
def test_local_destination_must_match_signed_primary_locator(expected, observed, matches):
    assert _local_endpoint_matches(expected, observed) is matches


def test_ipv6_packet_info_extracts_kernel_destination_and_bound_port():
    if not hasattr(socket, "IPV6_PKTINFO"):
        pytest.skip("Python does not expose IPV6_PKTINFO on this platform")
    destination = ipaddress.IPv6Address("2001:db8::1").packed
    ancillary = [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, destination + (3).to_bytes(4, "little"))]
    item = SimpleNamespace(family=socket.AF_INET6, getsockname=lambda: ("::", 49152, 0, 0))

    assert NLSDaemon._local_destination_endpoint(item, ancillary) == ("2001:db8::1", 49152)


def test_ipv4_packet_info_extracts_kernel_destination_and_bound_port():
    if not hasattr(socket, "IP_PKTINFO"):
        pytest.skip("Python does not expose IP_PKTINFO on this platform")
    # struct in_pktinfo: ifindex (4), spec_dst (4), ipi_addr/destination (4).
    ancillary = [(socket.IPPROTO_IP, socket.IP_PKTINFO, b"\x01\x00\x00\x00" + b"\x00" * 4 + socket.inet_aton("192.0.2.10"))]
    item = SimpleNamespace(family=socket.AF_INET, getsockname=lambda: ("0.0.0.0", 4242))

    assert NLSDaemon._local_destination_endpoint(item, ancillary) == ("192.0.2.10", 4242)


def test_missing_packet_info_fails_closed():
    item = SimpleNamespace(family=socket.AF_INET6, getsockname=lambda: ("::", 49152, 0, 0))
    assert NLSDaemon._local_destination_endpoint(item, []) is None
def test_runtime_uses_authoritative_local_rdr_primary_endpoint():
    class RuntimeStub:
        def __init__(self):
            self._local_endpoint_lock = threading.Lock()
            self._local_endpoint_cache = None
            self._local_endpoint_cache_expires = 0.0

        @staticmethod
        def _self_record():
            return ({"wan_endpoints": ["[2001:db8::1]:49152"]}, {"signature": "ignored"})

    runtime = RuntimeStub()
    assert HandshakeV2.local_destination_matches(runtime, ("2001:db8::1", 49152))
    assert not HandshakeV2.local_destination_matches(runtime, ("2001:db8::2", 49152))


def test_runtime_fails_closed_when_local_rdr_is_unavailable():
    class RuntimeStub:
        def __init__(self):
            self._local_endpoint_lock = threading.Lock()
            self._local_endpoint_cache = None
            self._local_endpoint_cache_expires = 0.0

        @staticmethod
        def _self_record():
            raise RuntimeError("directory unavailable")

    assert not HandshakeV2.local_destination_matches(
        RuntimeStub(), ("2001:db8::1", 49152)
    )

