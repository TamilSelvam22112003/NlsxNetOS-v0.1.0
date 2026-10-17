import json
from types import SimpleNamespace

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


def test_default_tun_mtu_is_safe_for_96_byte_nle2_overhead():
 from nls.config import TunConfig
 # Ethernet MTU 1500 minus 96 bytes of NLS outer/header/tag overhead is 1404.
 # The default 1400 keeps a small safety margin and avoids outer fragmentation.
 assert 1500 - 96 == 1404
 assert TunConfig().mtu == 1400
 assert TunConfig().mtu <= 1500 - 96


def test_operator_route_cache_invalidates_when_router_config_changes(monkeypatch, tmp_path):
 from services.router import config as router_config
 from nls import routing
 path = tmp_path / "router.yaml"
 monkeypatch.setattr(router_config, "PATH", path)
 path.write_text(
  "router:\n  nls_routes:\n    - prefix: 2001:db8:1::/64\n      router_id: router-a\n",
  encoding="utf-8",
 )
 first = routing.operator_routes()
 assert first == [{"prefix": "2001:db8:1::/64", "router_id": "router-a"}]
 # Different size guarantees a fingerprint change even on coarse-mtime filesystems.
 path.write_text(
  "router:\n  nls_routes:\n    - prefix: 2001:db8:22::/64\n      router_id: router-a\n",
  encoding="utf-8",
 )
 second = routing.operator_routes()
 assert second == [{"prefix": "2001:db8:22::/64", "router_id": "router-a"}]
 # Returned copies must not mutate the cached route set.
 second[0]["prefix"] = "2001:db8:dead::/64"
 assert routing.operator_routes() == [{"prefix": "2001:db8:22::/64", "router_id": "router-a"}]


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


def test_nls_status_reports_sessions_and_reason_counters(monkeypatch, tmp_path, capsys):
 from nls import config, daemon
 from tools.router_cli import commands

 cfg = config.NLSConfig(router_id="router-a", enabled=True)
 monkeypatch.setattr(config, "load", lambda: cfg)
 status_path = tmp_path / "nls-status.json"
 status_path.write_text(json.dumps({
  "directory_freshness_seconds": 17,
  "counters": {"rx": 12, "tx": 9, "drops": 1},
  "reason_counters": {"INNER_SRC_NOT_ALLOWED": 1},
  "sessions": [{
   "peer": "router-b", "state": "ESTABLISHED", "bytes_sent": 900,
   "bytes_received": 1200, "packets_sent": 3, "packets_received": 4,
   "rekey_age_seconds": 60, "ca_freshness_seconds": 17,
  }],
 }), encoding="utf-8")
 monkeypatch.setattr(daemon, "STATUS_PATH", status_path)
 commands.nls_status()
 output = capsys.readouterr().out
 assert "peer=router-b state=ESTABLISHED" in output
 assert "tx=3 packets/900 bytes" in output
 assert "rx=4 packets/1200 bytes" in output
 assert "CA_freshness=17s" in output
 assert "INNER_SRC_NOT_ALLOWED" in output


def test_doctor_checks_net_admin_directory_freshness_and_ca(monkeypatch, capsys):
 from nls import config
 from tools.router_cli import commands

 monkeypatch.setattr(config, "load", lambda: SimpleNamespace(
  enabled=True, tun=SimpleNamespace(enabled=True)
 ))
 monkeypatch.setattr(commands, "_has_cap_net_admin", lambda: True)
 monkeypatch.setattr(commands, "_router_ca_health", lambda: (20, True, "ca"))
 monkeypatch.setattr(commands, "frr_validate", lambda: (True, ""))
 monkeypatch.setattr(commands, "supported", lambda: True)
 monkeypatch.setattr(commands, "ubuntu_release", lambda: "24.04")
 monkeypatch.setattr(commands, "service_state", lambda _name: "active")
 monkeypatch.setattr(commands, "forwarding_state", lambda: True)
 monkeypatch.setattr(commands.shutil, "which", lambda _name: "/usr/bin/vtysh")
 assert commands.doctor(as_json=True) == 0
 data = json.loads(capsys.readouterr().out)
 assert data["cap_net_admin_for_vip"] is True
 assert data["directory_freshness_seconds"] == 20
 assert data["ca_reachable"] is True

 monkeypatch.setattr(commands, "_has_cap_net_admin", lambda: False)
 assert commands.doctor(as_json=True) == 1
 data = json.loads(capsys.readouterr().out)
 assert data["cap_net_admin_for_vip"] is False
