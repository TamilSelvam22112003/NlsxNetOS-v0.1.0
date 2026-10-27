import ipaddress
import struct
from types import SimpleNamespace
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from nls.daemon import NLSDaemon
from nls.endpoint_envelope import seal_endpoint_packet
from nls.identity import public_key_b64
from nls.replay import ReplayWindow
from security.trust.router_ca import store as ca_store


def _daemon():
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.identity_public = "this-router-key"
    daemon.cfg = SimpleNamespace(bind_interface="wan0")
    return daemon


def test_local_destination_matches_router_owned_router_ca_prefix(monkeypatch):
    daemon = _daemon()
    monkeypatch.setattr(ca_store, "active_entries", lambda: [
        SimpleNamespace(public_key="this-router-key", prefix="2001:db8:1::/64")
    ])
    run = Mock()
    monkeypatch.setattr("nls.daemon.subprocess.run", run)
    assert daemon._is_local_destination("2001:db8:1::10") is True
    run.assert_not_called()


def test_registered_server_endpoint_is_local_only_on_direct_lan_route(monkeypatch):
    daemon = _daemon()
    monkeypatch.setattr(ca_store, "active_entries", lambda: [])
    monkeypatch.setattr(ca_store, "lookup", lambda address: SimpleNamespace(prefix="2001:db8:ffff::80/128"))
    monkeypatch.setattr(
        "nls.daemon.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout="2001:db8:ffff::80 dev lan0 src 2001:db8:ffff::1\n"),
    )
    assert daemon._is_local_destination("2001:db8:ffff::80") is True


def test_registered_server_endpoint_via_next_hop_is_not_local(monkeypatch):
    daemon = _daemon()
    monkeypatch.setattr(ca_store, "active_entries", lambda: [])
    monkeypatch.setattr(ca_store, "lookup", lambda address: SimpleNamespace(prefix="2001:db8:ffff::80/128"))
    monkeypatch.setattr(
        "nls.daemon.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout="2001:db8:ffff::80 via 2001:db8:2::1 dev wan0\n"),
    )
    assert daemon._is_local_destination("2001:db8:ffff::80") is False


def test_registered_server_endpoint_not_local_if_kernel_route_lookup_fails(monkeypatch):
    daemon = _daemon()
    monkeypatch.setattr(ca_store, "active_entries", lambda: [])
    monkeypatch.setattr(ca_store, "lookup", lambda address: SimpleNamespace(prefix="2001:db8:ffff::80/128"))
    def fail(*args, **kwargs):
        raise OSError("ip command unavailable")
    monkeypatch.setattr("nls.daemon.subprocess.run", fail)
    assert daemon._is_local_destination("2001:db8:ffff::80") is False


def test_endpoint_response_uses_original_client_as_outer_destination(monkeypatch):
    """Server response is NLE2 to the client, then wrapped and routed via NLR1."""
    client_address = "2001:db8:abcd::10"
    server_address = "2001:db8:ffff::80"
    source_identity = Ed25519PrivateKey.generate()
    client_encryption_key = generate_private_key(public_exponent=65537, key_size=3072)
    response_packet = (
        struct.pack(
            "!IHBB16s16s",
            6 << 28, 0, 17, 64,
            ipaddress.IPv6Address(server_address).packed,
            ipaddress.IPv6Address(client_address).packed,
        )
        + b"response-canary"
    )
    endpoint_sid = bytes.fromhex("a2" * 16)
    endpoint_packet = seal_endpoint_packet(
        client_encryption_key.public_key(), source_identity,
        endpoint_sid, 0, client_address, response_packet,
    )
    source_entry = SimpleNamespace(
        public_key=public_key_b64(source_identity),
        prefix=f"{server_address}/128",
    )
    next_peer = SimpleNamespace(id="router-next", endpoint="[2001:db8:2::1]:4789")
    outbound = SimpleNamespace(
        peer_id=next_peer.id,
        session_id=bytes.fromhex("b3" * 16),
        send_key=b"k" * 32,
        tx_sequence=0,
        last_tx=0.0,
    )
    daemon = _daemon()
    daemon.identity_public = "client-side-router-identity"
    daemon.cfg.listen_port = 4789
    daemon.cfg.listen_address = "2001:db8:1::1"
    daemon.cfg.max_clock_skew_seconds = 120
    daemon.cfg.replay_window = 64
    daemon.endpoint_rx = {}
    daemon.sock = Mock()
    daemon.peers = {next_peer.id: next_peer}
    daemon.stats = {"tx": 0, "rx": 0, "drops": 0, "data_drops": 0}
    daemon._ingress_is_expected_endpoint_source = lambda _source, _ifindex: True
    daemon._session_for_destination = lambda destination: outbound
    daemon._original_router_ip = lambda: "2001:db8:1::1"
    monkeypatch.setattr(ca_store, "active_entries", lambda: [source_entry])
    monkeypatch.setattr(ca_store, "lookup", lambda _address: source_entry)
    monkeypatch.setattr("nls.daemon.socket.if_nametoindex", lambda _name: 9)
    send = Mock(return_value=len(endpoint_packet))
    monkeypatch.setattr("nls.daemon.send_transparent", send)

    daemon._handle_local_endpoint_packet(
        endpoint_packet, (server_address, 4789, 0, 4), client_address
    )

    assert send.call_count == 1
    assert send.call_args.args[2] == client_address
    assert send.call_args.args[3] == 4789
    assert send.call_args.args[1].startswith(b"NLR1")
    assert outbound.tx_sequence == 1
    assert daemon.stats["tx"] == 1
