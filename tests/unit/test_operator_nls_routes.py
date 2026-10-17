import pytest

from services.router import config as router_config


def test_operator_route_rejects_default_and_overlaps():
    data = {"router": {"interfaces": {}, "nls_routes": []}}
    router_config.add_nls_route(data, "10.10.0.0/16", "router-a")
    with pytest.raises(ValueError, match="default routes"):
        router_config.add_nls_route(data, "0.0.0.0/0", "router-b")
    with pytest.raises(ValueError, match="overlaps"):
        router_config.add_nls_route(data, "10.10.1.0/24", "router-b")
    with pytest.raises(ValueError, match="overlaps"):
        router_config.add_nls_route(data, "10.10.0.0/16", "router-b")
    assert data["router"]["nls_routes"] == [
        {"prefix": "10.10.0.0/16", "router_id": "router-a"}
    ]


def test_operator_route_rejects_host_bits_and_invalid_router_id():
    data = {"router": {"interfaces": {}, "nls_routes": []}}
    with pytest.raises(ValueError):
        router_config.add_nls_route(data, "10.10.1.1/24", "router-a")
    with pytest.raises(ValueError):
        router_config.add_nls_route(data, "10.10.0.0/24", "bad router id")
    assert data["router"]["nls_routes"] == []


def test_remove_operator_route_is_exact():
    data = {"router": {"interfaces": {}, "nls_routes": []}}
    router_config.add_nls_route(data, "2001:db8:100::/48", "router-v6")
    assert router_config.remove_nls_route(data, "2001:db8:100::/48")
    assert not router_config.remove_nls_route(data, "2001:db8:100::/48")
    assert data["router"]["nls_routes"] == []


def test_daemon_uses_precompiled_longest_prefix_routes_until_refresh(monkeypatch):
    import threading

    from nls.daemon import NLSDaemon

    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon._operator_route_cache = {4: {}, 6: {}}
    daemon._operator_route_prefix_lengths = {4: (), 6: ()}
    daemon._operator_route_refresh_at = 0.0
    daemon._operator_route_cache_lock = threading.RLock()
    route_rows = [
        {"prefix": "10.0.0.0/8", "router_id": "router-wide"},
        {"prefix": "10.1.0.0/16", "router_id": "router-specific"},
    ]
    calls = []

    def load_routes():
        calls.append(1)
        return list(route_rows)

    monkeypatch.setattr("nls.routing.operator_routes", load_routes)
    assert daemon._operator_route_for_destination("10.1.2.3") == "router-specific"
    assert daemon._operator_route_for_destination("10.2.3.4") == "router-wide"
    assert len(calls) == 1, "route config should not be read for every packet"
    compiled_before = daemon._operator_route_cache

    daemon._operator_route_refresh_at = 0.0
    assert daemon._operator_route_for_destination("10.2.3.4") == "router-wide"
    assert len(calls) == 2
    assert daemon._operator_route_cache is compiled_before, (
        "unchanged config should reuse the compiled longest-prefix index"
    )

    route_rows[:] = [{"prefix": "10.0.0.0/8", "router_id": "router-new"}]
    daemon._operator_route_refresh_at = 0.0
    assert daemon._operator_route_for_destination("10.1.2.3") == "router-new"
    assert len(calls) == 3, "route config should be polled after refresh deadline"
