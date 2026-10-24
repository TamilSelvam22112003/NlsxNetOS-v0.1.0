import pytest

import nls.config as nls_config


def test_metadata_mode_defaults_to_stronger_source_destination_policy():
    cfg = nls_config.NLSConfig()
    assert cfg.metadata_mode == "source-destination"


@pytest.mark.parametrize("mode", ["source-only", "source-destination"])
def test_metadata_mode_config_accepts_supported_values(tmp_path, monkeypatch, mode):
    config_path = tmp_path / "nls.yaml"
    config_path.write_text(f"nls:\n  metadata_mode: {mode}\n", encoding="utf-8")
    monkeypatch.setattr(nls_config, "CONFIG_PATH", config_path)
    cfg = nls_config.load()
    assert cfg.metadata_mode == mode


def test_metadata_mode_config_rejects_unknown_value(tmp_path, monkeypatch):
    config_path = tmp_path / "nls.yaml"
    config_path.write_text("nls:\n  metadata_mode: source-ish\n", encoding="utf-8")
    monkeypatch.setattr(nls_config, "CONFIG_PATH", config_path)
    with pytest.raises(ValueError, match="metadata_mode must be source-only or source-destination"):
        nls_config.load()
