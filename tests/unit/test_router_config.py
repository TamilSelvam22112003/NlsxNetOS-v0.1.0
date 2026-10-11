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
