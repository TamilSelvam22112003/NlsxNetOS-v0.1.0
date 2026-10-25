"""Tests for the explicit opt-in lab-only temporary vIP route switch."""
import yaml
import pytest

import nls.config as nls_config


def _write_config(path, document):
    path.write_text(yaml.safe_dump(document), encoding="utf-8")


def test_lab_temporary_route_is_disabled_by_default(tmp_path, monkeypatch):
    path = tmp_path / "nls.yaml"
    _write_config(path, {"nls": {}})
    monkeypatch.setattr(nls_config, "CONFIG_PATH", path)
    cfg = nls_config.load()
    assert cfg.deployment_mode == "production"
    assert cfg.vip_lab_temporary_route_enabled is False


def test_lab_temporary_route_requires_explicit_lab_mode(tmp_path, monkeypatch):
    path = tmp_path / "nls.yaml"
    _write_config(path, {"nls": {"vip": {"lab_temporary_route": {"enabled": True}}}})
    monkeypatch.setattr(nls_config, "CONFIG_PATH", path)
    with pytest.raises(ValueError, match="cannot be enabled in production"):
        nls_config.load()


def test_lab_temporary_route_requires_boolean_value(tmp_path, monkeypatch):
    path = tmp_path / "nls.yaml"
    _write_config(path, {"nls": {
        "deployment_mode": "lab",
        "vip": {"lab_temporary_route": {"enabled": "true"}},
    }})
    monkeypatch.setattr(nls_config, "CONFIG_PATH", path)
    with pytest.raises(ValueError, match="must be a boolean"):
        nls_config.load()


def test_lab_temporary_route_can_be_explicitly_enabled_in_lab_mode(tmp_path, monkeypatch):
    path = tmp_path / "nls.yaml"
    _write_config(path, {"nls": {
        "deployment_mode": "lab",
        "vip": {"lab_temporary_route": {"enabled": True}},
    }})
    monkeypatch.setattr(nls_config, "CONFIG_PATH", path)
    cfg = nls_config.load()
    assert cfg.deployment_mode == "lab"
    assert cfg.vip_lab_temporary_route_enabled is True
