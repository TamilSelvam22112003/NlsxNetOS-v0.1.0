import socket
import struct

import pytest

from nls.transparent import (
    TransparentForwardingError,
    parse_pktinfo,
)


def test_parse_ipv4_original_destination():
    destination = socket.inet_aton("198.51.100.22")
    data = struct.pack("=I4s4s", 7, socket.inet_aton("192.0.2.1"), destination)
    assert parse_pktinfo(socket.AF_INET, [(socket.IPPROTO_IP, getattr(socket, "IP_PKTINFO", 8), data)]) == ("198.51.100.22", 7)


def test_parse_ipv6_original_destination():
    destination = socket.inet_pton(socket.AF_INET6, "2001:db8::22")
    data = struct.pack("=16sI", destination, 12)
    level = getattr(socket, "SOL_IPV6", socket.IPPROTO_IPV6)
    kind = getattr(socket, "IPV6_PKTINFO", 50)
    assert parse_pktinfo(socket.AF_INET6, [(level, kind, data)]) == ("2001:db8::22", 12)


@pytest.mark.parametrize("family,data", [(socket.AF_INET, b"short"), (socket.AF_INET6, b"short")])
def test_truncated_packet_info_fails_closed(family, data):
    level = socket.IPPROTO_IP if family == socket.AF_INET else getattr(socket, "SOL_IPV6", socket.IPPROTO_IPV6)
    kind = getattr(socket, "IP_PKTINFO", 8) if family == socket.AF_INET else getattr(socket, "IPV6_RECVPKTINFO", 49)
    with pytest.raises(TransparentForwardingError, match="truncated"):
        parse_pktinfo(family, [(level, kind, data)])


def test_missing_packet_info_fails_closed():
    with pytest.raises(TransparentForwardingError, match="missing"):
        parse_pktinfo(socket.AF_INET6, [])
