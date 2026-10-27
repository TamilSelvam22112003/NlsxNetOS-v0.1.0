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
from pathlib import Path
from typing import Sequence

# Linux socket constants are not exported by every Python build.
_IP_TRANSPARENT = getattr(socket, "IP_TRANSPARENT", 19)
_IPV6_TRANSPARENT = getattr(socket, "IPV6_TRANSPARENT", 75)
_IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
_IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
_IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)
_IPV6_DONTFRAG = getattr(socket, "IPV6_DONTFRAG", 62)
_SOL_IPV6 = getattr(socket, "SOL_IPV6", socket.IPPROTO_IPV6)


FORWARD_STATE_PATH = Path(os.environ.get("NLSXNETOS_FORWARD_ROUTE_STATE", "/run/nlsxnetos/nls-forward-routes.json"))


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

def _require_net_admin() -> None:
    """Require CAP_NET_ADMIN, allowing the project's non-root systemd service."""
    if os.geteuid() == 0:
        return
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii")
        cap_line = next(line for line in status.splitlines() if line.startswith("CapEff:"))
        effective = int(cap_line.split()[1], 16)
    except (OSError, StopIteration, ValueError, IndexError) as exc:
        raise TransparentForwardingError("cannot verify CAP_NET_ADMIN capability") from exc
    if not effective & (1 << 12):
        raise TransparentForwardingError("destination-preserving forwarding requires CAP_NET_ADMIN")


def parse_pktinfo(family: int, ancillary: Sequence[tuple[int, int, bytes]]) -> tuple[str, int]:
    """Return the packet's original destination address and ingress ifindex."""
    for level, kind, data in ancillary:
        if family == socket.AF_INET and level == socket.IPPROTO_IP and kind == _IP_PKTINFO:
            if len(data) < 12:
                raise TransparentForwardingError("truncated IPv4 packet-info control message")
            ifindex, _spec_dst, destination = struct.unpack("=I4s4s", data[:12])
            return str(ipaddress.IPv4Address(destination)), ifindex
        if family == socket.AF_INET6 and level == _SOL_IPV6 and kind in (_IPV6_PKTINFO, _IPV6_RECVPKTINFO):
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
            sock.setsockopt(_SOL_IPV6, _IPV6_DONTFRAG, 0)
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
    Existing tables/rules are not flushed. A pre-existing table with the
    reserved name is treated as an error rather than modified unexpectedly.
    """
    _require_net_admin()
    if not 1 <= port <= 65535:
        raise ValueError("port must be in 1..65535")
    if not 1 <= mark <= 0xFFFFFFFF or not 1 <= table <= 2**31 - 1:
        raise ValueError("invalid fwmark or routing table")
    if not nft_table.replace("_", "").isalnum():
        raise ValueError("invalid nftables table name")

    _run(["nft", "--version"])
    existing = _run(["nft", "list", "table", "inet", nft_table], check=False)
    if existing.returncode == 0:
        raise TransparentForwardingError(
            f"nftables table inet {nft_table} already exists; inspect and remove it before setup"
        )
    table_created = False
    try:
        _run(["nft", "add", "table", "inet", nft_table])
        table_created = True
        _run([
            "nft", "add", "chain", "inet", nft_table, "prerouting",
            "{", "type", "filter", "hook", "prerouting", "priority", "mangle",
            ";", "policy", "accept", ";", "}",
        ])
        # Restrict interception to the configured UDP port and ingress WAN
        # interface, avoiding accidental interception of LAN-local endpoint-agent
        # packets which need to be delivered to this local daemon.
        _run([
            "nft", "add", "rule", "inet", nft_table, "prerouting",
            "meta", "nfproto", "ipv6", "meta", "l4proto", "udp",
            "iifname", interface, "udp", "dport", str(port),
            "tproxy", "to", f":{port}", "meta", "mark", "set", hex(mark), "accept",
        ])
        for family in ("-4", "-6"):
            _run(["ip", family, "rule", "add", "fwmark", hex(mark), "lookup", str(table)])
            local_route = "0.0.0.0/0" if family == "-4" else "::/0"
            _run(["ip", family, "route", "replace", "local", local_route, "dev", "lo", "table", str(table)])
    except Exception:
        for family in ("-4", "-6"):
            _run(["ip", family, "rule", "del", "fwmark", hex(mark), "lookup", str(table)], check=False)
            local_route = "0.0.0.0/0" if family == "-4" else "::/0"
            _run(["ip", family, "route", "del", "local", local_route, "dev", "lo", "table", str(table)], check=False)
        if table_created:
            _run(["nft", "delete", "table", "inet", nft_table], check=False)
        raise


def remove_tproxy(*, mark: int = 0x4, table: int = 100, nft_table: str = "nls_tproxy") -> None:
    """Remove only the dedicated TPROXY table/rules created for this profile."""
    _require_net_admin()
    for family in ("-4", "-6"):
        _run(["ip", family, "rule", "del", "fwmark", hex(mark), "lookup", str(table)], check=False)
        local_route = "0.0.0.0/0" if family == "-4" else "::/0"
        _run(["ip", family, "route", "del", "local", local_route, "dev", "lo", "table", str(table)], check=False)
    _run(["nft", "delete", "table", "inet", nft_table], check=False)


def sys_is_linux() -> bool:
    return os.name == "posix" and hasattr(socket, "AF_INET6") and os.path.exists("/proc/sys/net/ipv4")



def install_forward_routes(
    routes: Sequence[tuple[str, str]],
    *,
    interface: str,
    mark: int = 0x5,
    table: int = 200,
) -> None:
    """Install marked output routes through explicitly configured next-hop routers.

    Each tuple is (final-destination-prefix, next-hop-WAN-address). This table
    is separate from the TUN routes and from TPROXY's local-delivery table.
    """
    _require_net_admin()
    if FORWARD_STATE_PATH.exists():
        # Recover only the dedicated NLS route table from a prior unclean exit.
        remove_forward_routes(mark=mark, table=table)
    if not interface or not interface.replace("-", "").replace(".", "").isalnum():
        raise ValueError("a valid WAN interface is required")
    if not 1 <= mark <= 0xFFFFFFFF or not 1 <= table <= 2**31 - 1:
        raise ValueError("invalid output fwmark or routing table")
    _run(["ip", "-o", "link", "show", "dev", interface])
    installed = []
    try:
        for prefix, next_hop in routes:
            network = ipaddress.ip_network(prefix, strict=False)
            gateway = ipaddress.ip_address(next_hop)
            if network.version != gateway.version:
                raise ValueError(f"route {network} and next hop {gateway} use different IP families")
            if gateway.is_unspecified or gateway.is_multicast:
                raise ValueError(f"invalid next-hop address {gateway}")
            family = "-6" if network.version == 6 else "-4"
            _run(["ip", family, "route", "replace", str(network), "via", str(gateway),
                  "dev", interface, "table", str(table)])
            installed.append((family, str(network)))
        for family in ("-4", "-6"):
            _run(["ip", family, "rule", "add", "fwmark", hex(mark), "lookup", str(table)])
        FORWARD_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        FORWARD_STATE_PATH.write_text(
            __import__("json").dumps({"routes": installed, "mark": mark, "table": table}),
            encoding="utf-8",
        )
    except Exception:
        for family, network in installed:
            _run(["ip", family, "route", "del", network, "table", str(table)], check=False)
        for family in ("-4", "-6"):
            _run(["ip", family, "rule", "del", "fwmark", hex(mark), "lookup", str(table)], check=False)
        raise


def remove_forward_routes(*, mark: int = 0x5, table: int = 200) -> None:
    """Remove the destination-preserving output table recorded by install_forward_routes."""
    _require_net_admin()
    try:
        import json
        state = json.loads(FORWARD_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {"routes": []}
    actual_mark = int(state.get("mark", mark))
    actual_table = int(state.get("table", table))
    for family, network in state.get("routes", []):
        _run(["ip", family, "route", "del", network, "table", str(actual_table)], check=False)
    for family in ("-4", "-6"):
        _run(["ip", family, "rule", "del", "fwmark", hex(actual_mark), "lookup", str(actual_table)], check=False)
    try:
        FORWARD_STATE_PATH.unlink()
    except FileNotFoundError:
        pass
