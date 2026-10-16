from services.router import config as router_config


def test_router_config_round_trip(tmp_path, monkeypatch):
    path = tmp_path / "router.yaml"
    monkeypatch.setattr(router_config, "PATH", path)
    data = router_config.load()
    data["router"]["interfaces"]["eth0"] = {
        "addresses": ["2001:db8:1::1/64"],
        "nls_role": "lan",
        "enabled": True,
    }
    router_config.save(data)
    loaded = router_config.load()
    assert loaded["router"]["interfaces"]["eth0"]["nls_role"] == "lan"
    assert loaded["router"]["interfaces"]["eth0"]["addresses"] == ["2001:db8:1::1/64"]


import pytest


@pytest.mark.parametrize("prefix", ["not-a-prefix", "0.0.0.0/0", "::/0"])
def test_nls_route_rejects_invalid_or_default_prefix(prefix):
    with pytest.raises(ValueError):
        router_config.validate_nls_route(prefix, "router-b", [])


def test_nls_route_rejects_overlapping_operator_prefixes():
    existing = [{"prefix": "2001:db8:100::/48", "router_id": "router-b"}]
    with pytest.raises(ValueError, match="overlaps configured route"):
        router_config.validate_nls_route("2001:db8:100::/64", "router-c", existing)


def test_nls_route_rejects_unknown_router_id():
    with pytest.raises(ValueError, match="unknown NLS router ID"):
        router_config.validate_nls_route(
            "2001:db8:200::/48", "not-enrolled", [], known_router_ids={"router-a", "router-b"}
        )


def test_nls_route_rejects_local_prefix_overlap():
    with pytest.raises(ValueError, match="overlaps local prefix"):
        router_config.validate_nls_route(
            "2001:db8:100::/48", "router-b", [], local_prefixes=["2001:db8:100::/64"]
        )


def test_nls_route_rejects_address_family_mismatch():
    with pytest.raises(ValueError, match="address-family mismatch"):
        router_config.validate_nls_route(
            "2001:db8:200::/48", "router-b", [], expected_family=4
        )


def test_invalid_nls_route_does_not_mutate_running_config():
    import copy
    data = {"router": {"nls_routes": [{"prefix": "2001:db8:100::/48", "router_id": "router-b"}]}}
    before = copy.deepcopy(data)
    with pytest.raises(ValueError):
        router_config.add_nls_route(data, "2001:db8:100::/64", "router-c")
    assert data == before
