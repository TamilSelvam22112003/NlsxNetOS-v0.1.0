import ipaddress
import struct
from types import SimpleNamespace
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from nls.daemon import NLSDaemon
from nls.endpoint_session import new_init, respond_to_init, seal_data
from nls.identity import public_key_b64, unb64
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


def test_endpoint_response_uses_nle3_and_authenticated_hop_route(monkeypatch):
    """Endpoint-agent NLE3 response is wrapped by the router for the client."""
    client_address = "2001:db8:abcd::10"
    server_address = "2001:db8:ffff::80"
    client_identity = Ed25519PrivateKey.generate()
    server_identity = Ed25519PrivateKey.generate()
    init_packet, _pending = new_init(client_identity, server_identity.public_key().public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    ))
    _response, server_session = respond_to_init(
        init_packet, server_identity,
        {client_identity.public_key().public_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
            format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
        ): client_identity.public_key()},
    )
    response_packet = (
        struct.pack(
            "!IHBB16s16s", 6 << 28, 0, 17, 64,
            ipaddress.IPv6Address(server_address).packed,
            ipaddress.IPv6Address(client_address).packed,
        ) + b"response-canary"
    )
    endpoint_packet = seal_data(server_session, response_packet, client_address)
    server_entry = SimpleNamespace(
        id="server", public_key=public_key_b64(server_identity),
        prefix=f"{server_address}/128",
    )
    client_entry = SimpleNamespace(
        id="client", public_key=public_key_b64(client_identity),
        prefix=f"{client_address}/128",
    )
    hop = SimpleNamespace(
        peer_id="router-next", session_id=bytes.fromhex("b3" * 16),
        send_key=b"k" * 32, tx_sequence=0, last_tx=0.0,
        peer_identity=unb64(client_entry.public_key),
    )
    daemon = _daemon()
    daemon.identity_public = "local-router"
    daemon.cfg.listen_port = 4789
    daemon.stats = {"tx": 0, "rx": 0, "drops": 0, "data_drops": 0}
    daemon._last_received_interface_index = 4
    daemon._ingress_is_expected_endpoint_source = lambda _source, _ifindex: True
    daemon._session_for_destination = lambda _destination: hop
    daemon._send_endpoint_over_hop = Mock()
    monkeypatch.setattr(
        ca_store, "lookup",
        lambda address: server_entry if str(address) == server_address else client_entry,
    )
    daemon._handle_local_endpoint_packet(
        endpoint_packet, (server_address, 4789, 0, 4), client_address
    )
    daemon._send_endpoint_over_hop.assert_called_once_with(client_address, endpoint_packet, hop)
    assert daemon.stats["tx"] == 1
    assert daemon.stats["drops"] == 0
