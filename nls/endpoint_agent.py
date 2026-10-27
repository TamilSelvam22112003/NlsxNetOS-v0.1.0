"""NLS server-side endpoint agent.

Receives opaque NLE2 envelopes forwarded by the destination router, verifies
the source router's Router-CA identity/signature, decrypts with the server's
private encryption key, and injects the recovered IP packet into a TUN device
so the local server IP stack can deliver it to the application.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import socket
import subprocess
import select
import secrets
import json
import signal
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from security.trust.router_ca import store as ca_store
from .endpoint_envelope import HEADER, EndpointEnvelopeError, open_endpoint_packet, seal_endpoint_packet
from .identity import load_or_create, public_key_b64, unb64, decode_public_key
from .replay import ReplayWindow
from .rsa import public_key_b64 as rsa_public_key_b64
from .tun import TunDevice

ENDPOINT_ROUTE_STATE = Path("/run/nlsxnetos/nls-endpoint-agent-routes.json")

LOG = logging.getLogger("nlsxnetos.endpoint-agent")


class EndpointAgentProcessor:
    """Verify/decrypt endpoint packets with Router-CA-pinned origin identities."""

    def __init__(self, private_key, trusted_sources: dict[bytes, Ed25519PublicKey],
                 *, max_clock_skew: int = 120, replay_window: int = 64):
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError("endpoint agent requires an RSA private encryption key")
        if not 1 <= replay_window <= 4096:
            raise ValueError("replay_window must be 1..4096")
        self.private_key = private_key
        self.trusted_sources = dict(trusted_sources)
        self.max_clock_skew = max_clock_skew
        self.replay_window_size = replay_window
        self.replay = {}

    def process(self, packet: bytes, destination: str) -> bytes:
        if not isinstance(packet, bytes) or len(packet) < HEADER.size:
            raise EndpointEnvelopeError("NLE2 endpoint envelope is truncated")
        try:
            magic, version, session_id, source_identity, sequence, *_ = HEADER.unpack_from(packet)
        except Exception as exc:
            raise EndpointEnvelopeError("invalid NLE2 endpoint header") from exc
        if magic != b"NLE2" or version != 1:
            raise EndpointEnvelopeError("unsupported endpoint envelope")
        source_key = self.trusted_sources.get(source_identity)
        if source_key is None:
            raise EndpointEnvelopeError("NLE2 origin identity is not trusted by Router-CA")
        replay_key = (source_identity, session_id)
        window = self.replay.setdefault(
            replay_key, ReplayWindow(self.replay_window_size)
        )
        if not window.can_accept(sequence):
            raise EndpointEnvelopeError("NLE2 endpoint replay detected")
        opened = open_endpoint_packet(
            self.private_key,
            source_key,
            packet,
            expected_destination=destination,
            expected_session_id=session_id,
            max_clock_skew=self.max_clock_skew,
        )
        if not window.mark(opened["sequence"]):
            raise EndpointEnvelopeError("NLE2 endpoint replay detected")
        return opened["payload"]


def _load_rsa_private_key(path: str) -> RSAPrivateKey:
    raw = Path(path).read_bytes()
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("endpoint encryption key must be an RSA private key")
    return key


def _packet_destination(packet: bytes) -> str:
    if not packet or packet[0] >> 4 != 6 or len(packet) < 40:
        raise ValueError("endpoint agent currently supports complete IPv6 packets only")
    return str(ipaddress.IPv6Address(packet[24:40]))


def _install_routes(remote_prefixes: list[str], tun_name: str, gateway: str,
                    interface: str, *, mark: int = 0x6, table: int = 300) -> None:
    gateway_ip = ipaddress.ip_address(gateway)
    if gateway_ip.version != 6 or gateway_ip.is_unspecified or gateway_ip.is_multicast or gateway_ip.is_link_local:
        raise ValueError("endpoint-agent gateway must be a global unicast IPv6 address")
    installed_main = []
    installed_policy = []
    try:
        for prefix in remote_prefixes:
            network = ipaddress.ip_network(prefix, strict=False)
            if network.version != 6:
                raise ValueError("endpoint-agent remote prefixes must be IPv6")
            existing = subprocess.run(
                ["ip", "-6", "route", "show", "exact", str(network)],
                check=True, capture_output=True, text=True,
            )
            if existing.stdout.strip():
                raise RuntimeError(f"route {network} already exists; refusing to overwrite it")
            subprocess.run(["ip", "-6", "route", "add", str(network), "dev", tun_name], check=True)
            installed_main.append(str(network))
            subprocess.run(
                ["ip", "-6", "route", "replace", str(network), "via", str(gateway_ip),
                 "dev", interface, "table", str(table)],
                check=True,
            )
            installed_policy.append(str(network))
        subprocess.run(
            ["ip", "-6", "rule", "add", "fwmark", hex(mark), "lookup", str(table)],
            check=True,
        )
        ENDPOINT_ROUTE_STATE.parent.mkdir(parents=True, exist_ok=True)
        ENDPOINT_ROUTE_STATE.write_text(json.dumps({
            "main_routes": installed_main, "policy_routes": installed_policy,
            "mark": mark, "table": table,
        }), encoding="utf-8")
    except Exception:
        for prefix in installed_main:
            subprocess.run(["ip", "-6", "route", "del", prefix], check=False)
        for prefix in installed_policy:
            subprocess.run(["ip", "-6", "route", "del", prefix, "table", str(table)], check=False)
        subprocess.run(["ip", "-6", "rule", "del", "fwmark", hex(mark), "lookup", str(table)], check=False)
        raise


def _remove_routes(*, mark: int = 0x6, table: int = 300) -> None:
    try:
        state = json.loads(ENDPOINT_ROUTE_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {"main_routes": [], "policy_routes": [], "mark": mark, "table": table}
    actual_mark = int(state.get("mark", mark))
    actual_table = int(state.get("table", table))
    for prefix in state.get("main_routes", []):
        subprocess.run(["ip", "-6", "route", "del", prefix], check=False)
    for prefix in state.get("policy_routes", []):
        subprocess.run(["ip", "-6", "route", "del", prefix, "table", str(actual_table)], check=False)
    subprocess.run(["ip", "-6", "rule", "del", "fwmark", hex(actual_mark), "lookup", str(actual_table)], check=False)
    try:
        ENDPOINT_ROUTE_STATE.unlink()
    except FileNotFoundError:
        pass


def run(*, listen_address: str, listen_port: int, private_key_path: str,
        identity_key_path: str, tun_name: str, mtu: int, gateway: str,
        interface: str, remote_prefixes: list[str],
        max_clock_skew: int = 120, replay_window: int = 64) -> None:
    address = ipaddress.ip_address(listen_address)
    if address.version != 6 or address.is_unspecified or address.is_multicast:
        raise ValueError("endpoint agent requires an exact unicast IPv6 listen address")
    if not 1 <= listen_port <= 65535:
        raise ValueError("listen_port must be in 1..65535")
    if mtu < 576:
        raise ValueError("TUN MTU must be >= 576")

    identity = load_or_create(identity_key_path)
    identity_public = public_key_b64(identity)
    private_key = _load_rsa_private_key(private_key_path)
    encryption_public = rsa_public_key_b64(private_key)
    entries = ca_store.active_entries()
    local_entry = next(
        (entry for entry in entries
         if entry.public_key == identity_public
         and entry.encryption_public_key == encryption_public
         and address in ipaddress.ip_network(entry.prefix, strict=False)),
        None,
    )
    if local_entry is None:
        raise RuntimeError("server endpoint identity/encryption key is not registered and active in Router-CA")

    trusted_sources = {}
    for entry in entries:
        try:
            trusted_sources[unb64(entry.public_key)] = decode_public_key(entry.public_key)
        except (ValueError, TypeError):
            continue
    processor = EndpointAgentProcessor(
        private_key, trusted_sources,
        max_clock_skew=max_clock_skew, replay_window=replay_window,
    )

    tun = TunDevice(tun_name).open()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    endpoint_tx = {}
    routes_installed = False
    try:
        subprocess.run(["ip", "link", "set", "dev", tun.name, "mtu", str(mtu)], check=True)
        subprocess.run(["ip", "link", "set", "dev", tun.name, "up"], check=True)
        _install_routes(remote_prefixes, tun.name, gateway, interface)
        routes_installed = True
        sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x6)
        sock.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_DONTFRAG", 62), 0)
        sock.bind((str(address), listen_port))
        LOG.info("NLS endpoint agent listening on [%s]:%d; TUN=%s", address, listen_port, tun.name)
        running = True
        def _stop(*_args):
            nonlocal running
            running = False
        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        while running:
            ready, _, _ = select.select([sock, tun], [], [], 1.0)
            for item in ready:
                if item is sock:
                    packet, peer = sock.recvfrom(65535)
                    try:
                        payload = processor.process(packet, str(address))
                        tun.write(payload)
                        LOG.debug("accepted signed NLE2 packet from %s", peer)
                    except Exception as exc:
                        LOG.warning("NLE2 packet rejected from %s: %s", peer, exc)
                else:
                    try:
                        payload = tun.read()
                    except BlockingIOError:
                        continue
                    try:
                        destination = _packet_destination(payload)
                        destination_entry = ca_store.lookup(destination)
                        if destination_entry is None or not destination_entry.encryption_public_key:
                            raise ValueError("destination has no active Router-CA encryption key")
                        endpoint_sid, sequence = endpoint_tx.get(
                            destination_entry.id, (secrets.token_bytes(16), 0)
                        )
                        envelope = seal_endpoint_packet(
                            destination_entry.encryption_public_key, identity,
                            endpoint_sid, sequence, destination, payload,
                        )
                        sock.sendto(envelope, (destination, listen_port))
                        endpoint_tx[destination_entry.id] = (endpoint_sid, sequence + 1)
                    except Exception as exc:
                        LOG.warning("server response could not be wrapped for NLS: %s", exc)
    finally:
        sock.close()
        tun.close()
        if routes_installed:
            _remove_routes()


def main() -> None:
    parser = argparse.ArgumentParser(description="NLS server-side endpoint decryptor")
    parser.add_argument("--listen-address", required=True, help="exact server IPv6 address")
    parser.add_argument("--listen-port", type=int, default=4789)
    parser.add_argument("--private-key", default="/var/lib/nlsxnetos/identity/rsa-encryption.pem")
    parser.add_argument("--identity-key", default="/var/lib/nlsxnetos/identity/ed25519.key")
    parser.add_argument("--tun", default="nls-endpoint0")
    parser.add_argument("--mtu", type=int, default=1280)
    parser.add_argument("--gateway", required=True, help="local NLS router's IPv6 LAN address")
    parser.add_argument("--interface", required=True, help="server LAN interface")
    parser.add_argument("--remote-prefix", action="append", required=True,
                        help="remote IPv6 prefix routed through the endpoint agent; repeat as needed")
    parser.add_argument("--max-clock-skew", type=int, default=120)
    parser.add_argument("--replay-window", type=int, default=64)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    run(
        listen_address=args.listen_address,
        listen_port=args.listen_port,
        private_key_path=args.private_key,
        identity_key_path=args.identity_key,
        tun_name=args.tun,
        mtu=args.mtu,
        gateway=args.gateway,
        interface=args.interface,
        remote_prefixes=args.remote_prefix,
        max_clock_skew=args.max_clock_skew,
        replay_window=args.replay_window,
    )


if __name__ == "__main__":
    main()
