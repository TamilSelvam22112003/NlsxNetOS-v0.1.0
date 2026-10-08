from services.router.config import load, save


def test_router_config_round_trip(tmp_path, monkeypatch):
    path = tmp_path / "router.yaml"
    monkeypatch.setattr("nlsxnetos.router_config.PATH", path)
    data = load()
    data["router"]["interfaces"]["eth0"] = {
        "addresses": ["2001:db8:1::1/64"],
        "nls_role": "lan",
        "enabled": True,
    }
    save(data)
    loaded = load()
    assert loaded["router"]["interfaces"]["eth0"]["nls_role"] == "lan"
    assert loaded["router"]["interfaces"]["eth0"]["addresses"] == ["2001:db8:1::1/64"]
