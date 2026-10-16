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
