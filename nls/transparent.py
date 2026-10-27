"""Linux primitives for destination-preserving NLS interception.

These helpers install a narrowly scoped UDP TPROXY path and expose the
original destination address. They do not by themselves implement the NLS
relay state machine; the daemon must authenticate/decrypt an NLR1 layer,
validate its peer/session/replay state, and forward only to an authorized
next hop before enabling this interception in production.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import struct
import subprocess
from dataclasses import dataclass
from typing import Sequence

# Linux socket constants are not exported by every Python build.
_IP_TRANSPARENT = getattr(socket, "IP_TRANSPARENT", 19)
_IPV6_TRANSPARENT = getattr(socket, "IPV6_TRANSPARENT", 75)
_IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
_IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
_IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)
_SOL_IPV6 = getattr(socket, "SOL_IPV6", socket.IPPROTO_IPV6)


class TransparentForwardingError(RuntimeError):
    """Raised when transparent forwarding cannot be configured safely."""


@dataclass(frozen=True)
class ReceivedDatagram:
    payload: bytes
    peer: tuple
    destination_address: str
    interface_index: int


def _run(args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), check=check, capture_output=True, text=True)


def parse_pktinfo(family: int, ancillary: Sequence[tuple[int, int, bytes]]) -> tuple[str, int]:
    """Return the packet's original destination address and ingress ifindex."""
    for level, kind, data in ancillary:
        if family == socket.AF_INET and level == socket.IPPROTO_IP and kind == _IP_PKTINFO:
            if len(data) < 12:
                raise TransparentForwardingError("truncated IPv4 packet-info control message")
            ifindex, _spec_dst, destination = struct.unpack("=I4s4s", data[:12])
            return str(ipaddress.IPv4Address(destination)), ifindex
        if family == socket.AF_INET6 and level == _SOL_IPV6 and kind == _IPV6_PKTINFO:
            if len(data) < 20:
                raise TransparentForwardingError("truncated IPv6 packet-info control message")
            destination, ifindex = struct.unpack("=16sI", data[:20])
            return str(ipaddress.IPv6Address(destination)), ifindex
    raise TransparentForwardingError("original destination packet-info is missing; refusing to forward")


def create_transparent_socket(address: str, port: int, *, interface: str = "") -> socket.socket:
    """Create a Linux transparent UDP socket that retains original-destination metadata."""
    if not sys_is_linux():
        raise TransparentForwardingError("destination-preserving interception requires Linux")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be in 1..65535")
    ip = ipaddress.ip_address(address)
    family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET:
            sock.setsockopt(socket.IPPROTO_IP, _IP_TRANSPARENT, 1)
            sock.setsockopt(socket.IPPROTO_IP, _IP_PKTINFO, 1)
        else:
            sock.setsockopt(_SOL_IPV6, _IPV6_TRANSPARENT, 1)
            sock.setsockopt(_SOL_IPV6, _IPV6_RECVPKTINFO, 1)
        if interface:
            if not hasattr(socket, "SO_BINDTODEVICE"):
                raise TransparentForwardingError("SO_BINDTODEVICE is unavailable")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\\0")
        sock.bind((str(ip), port))
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise



def _source_pktinfo(family: int, source_address: str, interface_index: int) -> tuple[int, int, bytes]:
    """Build the ancillary control message that selects the emitting relay's WAN source."""
    source = ipaddress.ip_address(source_address)
    if source.is_unspecified or source.is_multicast:
        raise ValueError("source address must be a unicast WAN locator")
    if interface_index < 0:
        raise ValueError("interface index must be non-negative")
    if family == socket.AF_INET and source.version == 4:
        data = struct.pack("=I4s4s", interface_index, source.packed, bytes(4))
        return socket.IPPROTO_IP, _IP_PKTINFO, data
    if family == socket.AF_INET6 and source.version == 6:
        data = struct.pack("=16sI", source.packed, interface_index)
        return _SOL_IPV6, _IPV6_PKTINFO, data
    raise ValueError("source address family does not match transparent socket")


def send_transparent(
    sock: socket.socket,
    payload: bytes,
    destination_address: str,
    destination_port: int,
    source_address: str,
    *,
    interface_index: int = 0,
) -> int:
    """Send while preserving the final destination and selecting this relay's WAN source."""
    destination = ipaddress.ip_address(destination_address)
    if not 1 <= destination_port <= 65535:
        raise ValueError("destination port must be in 1..65535")
    if sock.family != (socket.AF_INET if destination.version == 4 else socket.AF_INET6):
        raise ValueError("destination address family does not match transparent socket")
    level, kind, data = _source_pktinfo(sock.family, source_address, interface_index)
    target = (str(destination), destination_port)
    if destination.version == 6:
        target = (str(destination), destination_port, 0, interface_index)
    return sock.sendmsg([payload], [(level, kind, data)], 0, target)

def recv_transparent(sock: socket.socket, *, max_size: int = 65535) -> ReceivedDatagram:
    """Receive a datagram and fail closed if the original destination is unknown."""
    family = sock.family
    ancillary_size = socket.CMSG_SPACE(20 if family == socket.AF_INET6 else 12)
    payload, ancillary, flags, peer = sock.recvmsg(max_size, ancillary_size)
    if flags & getattr(socket, "MSG_CTRUNC", 0):
        raise TransparentForwardingError("truncated ancillary data; original destination is not trustworthy")
    destination, ifindex = parse_pktinfo(family, ancillary)
    return ReceivedDatagram(payload, peer, destination, ifindex)


def install_tproxy(*, port: int, mark: int = 0x4, table: int = 100, nft_table: str = "nls_tproxy") -> None:
    """Install dedicated IPv4/IPv6 policy-routing rules and an nftables TPROXY rule.

    The rules intercept only UDP traffic addressed to the configured NLS port.
    Existing tables/rules are not flushed. Run as root on a dedicated router.
    """
    if os.geteuid() != 0:
        raise TransparentForwardingError("TPROXY setup requires root")
    if not 1 <= port <= 65535:
        raise ValueError("port must be in 1..65535")
    if not 1 <= mark <= 0xFFFFFFFF or not 1 <= table <= 2**31 - 1:
        raise ValueError("invalid fwmark or routing table")
    if not nft_table.replace("_", "").isalnum():
        raise ValueError("invalid nftables table name")

    # Ensure nft exists before modifying policy routing.
    _run(["nft", "--version"])
    _run(["nft", "add", "table", "inet", nft_table], check=False)
    _run(["nft", "add", "chain", "inet", nft_table, "prerouting",
          "{", "type", "filter", "hook", "prerouting", "priority", "mangle", ";", "policy", "accept", ";", "}"], check=False)
    _run(["nft", "add", "rule", "inet", nft_table, "prerouting",
          "meta", "l4proto", "udp", "udp", "dport", str(port),
          "tproxy", "to", f":{port}", "meta", "mark", "set", hex(mark), "accept"])

    for family in ("-4", "-6"):
        _run(["ip", family, "rule", "add", "fwmark", hex(mark), "lookup", str(table)], check=False)
        local_route = "0.0.0.0/0" if family == "-4" else "::/0"
        _run(["ip", family, "route", "replace", "local", local_route, "dev", "lo", "table", str(table)])


def remove_tproxy(*, mark: int = 0x4, table: int = 100, nft_table: str = "nls_tproxy") -> None:
    """Remove only the dedicated TPROXY table/rules created for this profile."""
    if os.geteuid() != 0:
        raise TransparentForwardingError("TPROXY teardown requires root")
    for family in ("-4", "-6"):
        _run(["ip", family, "rule", "del", "fwmark", hex(mark), "lookup", str(table)], check=False)
        local_route = "0.0.0.0/0" if family == "-4" else "::/0"
        _run(["ip", family, "route", "del", "local", local_route, "dev", "lo", "table", str(table)], check=False)
    _run(["nft", "delete", "table", "inet", nft_table], check=False)


def sys_is_linux() -> bool:
    return os.name == "posix" and hasattr(socket, "AF_INET6") and os.path.exists("/proc/sys/net/ipv4")
