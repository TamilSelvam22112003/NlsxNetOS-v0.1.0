import pytest

import nls.config as config


def test_destination_preserving_mode_requires_explicit_next_hop(monkeypatch, tmp_path):
    path = tmp_path / "nls.yaml"
    path.write_text(
        "nls:\n  enabled: true\n  forwarding_mode: destination_preserving\n"
        "  auto_router_ca: false\n  bind_interface: eth0\n  peers: []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config, "CONFIG_PATH", path)
    with pytest.raises(ValueError, match="explicit next-hop peers"):
        config.load()


def test_destination_preserving_mode_rejects_automatic_direct_routes(monkeypatch, tmp_path):
    path = tmp_path / "nls.yaml"
    path.write_text(
        "nls:\n  forwarding_mode: destination_preserving\n"
        "  auto_router_ca: true\n  bind_interface: eth0\n  peers: []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config, "CONFIG_PATH", path)
    with pytest.raises(ValueError, match="auto_router_ca: false"):
        config.load()


def test_legacy_mode_remains_default(monkeypatch, tmp_path):
    path = tmp_path / "nls.yaml"
    path.write_text("nls: {}\n", encoding="utf-8")
    monkeypatch.setattr(config, "CONFIG_PATH", path)
    assert config.load().forwarding_mode == "legacy"
