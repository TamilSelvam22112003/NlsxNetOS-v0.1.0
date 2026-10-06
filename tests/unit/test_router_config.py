from nlsxnetos.router_config import load, save


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


def test_cisco_interface_alias_resolves_deterministically(monkeypatch):
    from nlsxnetos import router_config

    monkeypatch.setattr(
        router_config,
        "_linux_interfaces",
        lambda: ["enp0s3", "enp0s8", "enp0s9", "enp0s10"],
    )
    monkeypatch.setattr(router_config, "validate_linux_interface", lambda name: None)

    data = {"router": {"interfaces": {}}}
    assert router_config.normalize_interface_name("gigabitethernet 0/0".replace(" ", "")) == "g0/0"
    assert router_config.resolve_interface("g0/0", data) == "enp0s3"
    assert router_config.resolve_interface("g0/2", data) == "enp0s9"
