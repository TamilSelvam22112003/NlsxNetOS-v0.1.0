import pytest
from nls.config import endpoint
def test_endpoint_parser():
 assert endpoint("127.0.0.1:4789")==("127.0.0.1",4789)
 assert endpoint("[::1]:4789")==("::1",4789)


def test_nle2_security_defaults():
 from nls.config import NLSConfig, TunConfig
 cfg = NLSConfig()
 assert cfg.replay_window == 128
 assert cfg.enforce_inner_source_prefix is True
 assert TunConfig().mtu == 1400


def test_configurable_replay_window_bounds():
 from nls.replay import ReplayWindow
 for size in (1, 128, 4096):
  assert ReplayWindow(size).size == size
 for size in (0, 4097):
  with pytest.raises(ValueError, match="1..4096"):
   ReplayWindow(size)


def test_rekey_limits_are_configurable(monkeypatch, tmp_path):
 from nls import config
 monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "nls.yaml")
 config.CONFIG_PATH.write_text(
  "nls:\n  rekey_packet_limit: 100\n  rekey_seconds: 60\n  rekey_overlap_seconds: 2\n",
  encoding="utf-8",
 )
 cfg = config.load()
 assert cfg.rekey_packet_limit == 100
 assert cfg.rekey_seconds == 60
 assert cfg.rekey_overlap_seconds == 2


@pytest.mark.parametrize(
 "key,value",
 [("rekey_packet_limit", 1), ("rekey_packet_limit", (1 << 32) + 1),
  ("rekey_seconds", 0), ("rekey_seconds", 86401),
  ("rekey_overlap_seconds", 0), ("rekey_overlap_seconds", 61)],
)
def test_invalid_rekey_limits_rejected(monkeypatch, tmp_path, key, value):
 from nls import config
 monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "nls.yaml")
 config.CONFIG_PATH.write_text(f"nls:\n  {key}: {value}\n", encoding="utf-8")
 with pytest.raises(ValueError, match="rekey_"):
  config.load()
