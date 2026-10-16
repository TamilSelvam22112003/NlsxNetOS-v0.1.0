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
