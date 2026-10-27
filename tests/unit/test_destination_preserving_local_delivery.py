from types import SimpleNamespace
from unittest.mock import Mock

from nls.daemon import NLSDaemon
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
