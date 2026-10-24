from __future__ import annotations

import copy

import pytest

from services.router import config as router_config
from tools.router_cli import commands


def _records():
    return {
        "router-b": {
            "router_id": "router-b",
            "status": "ACTIVE",
            "valid_until": 4_000_000_000,
            "certificate_serial": "1234",
            "prefixes": ["2001:db8:200::/48"],
        }
    }


def test_nls_route_cli_validates_against_signed_directory_and_local_prefixes(monkeypatch):
    monkeypatch.setattr(commands, "_verified_directory_records", _records)
    data = {
        "router": {
            "interfaces": {"lan0": {"addresses": ["2001:db8:1::1/64"]}},
            "nls_routes": [],
        }
    }
    ok, next_mode = commands._config_command(
        ["nls", "route", "2001:db8:200::/48", "via", "router-b"], data
    )
    assert (ok, next_mode) == (True, None)
    assert data["router"]["nls_routes"] == [
        {"prefix": "2001:db8:200::/48", "router_id": "router-b"}
    ]


@pytest.mark.parametrize(
    "tokens",
    [
        ["nls", "route", "not-a-prefix", "via", "router-b"],
        ["nls", "route", "::/0", "via", "router-b"],
        ["nls", "route", "0.0.0.0/0", "via", "router-b"],
        ["nls", "route", "2001:db8:1::/64", "via", "router-b"],
        ["nls", "route", "2001:db8:200::/48", "via", "unknown-router"],
        ["nls", "route", "192.0.2.0/24", "via", "router-b"],
    ],
)
def test_invalid_nls_route_command_does_not_mutate_config(monkeypatch, tokens):
    monkeypatch.setattr(commands, "_verified_directory_records", _records)
    data = {
        "router": {
            "interfaces": {"lan0": {"addresses": ["2001:db8:1::1/64"]}},
            "nls_routes": [{"prefix": "2001:db8:300::/48", "router_id": "router-b"}],
        }
    }
    before = copy.deepcopy(data)
    with pytest.raises(ValueError):
        commands._config_command(tokens, data)
    assert data == before


def test_show_running_config_includes_operator_nls_routes(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(router_config, "PATH", tmp_path / "router.yaml")
    data = router_config._default()
    data["router"]["nls_routes"] = [
        {"prefix": "2001:db8:200::/48", "router_id": "router-b"}
    ]
    router_config.save(data)
    commands._show_running_config()
    assert "nls route 2001:db8:200::/48 via router-b" in capsys.readouterr().out
