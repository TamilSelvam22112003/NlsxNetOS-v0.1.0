"""Unit tests for scoped lab-only vIP return-route ownership."""
import json
import subprocess
from types import SimpleNamespace

import pytest

from nls.v2_runtime import HandshakeV2


def _runtime(mode="lab", enabled=True):
    runtime = object.__new__(HandshakeV2)
    runtime.owner = SimpleNamespace(cfg=SimpleNamespace(
        deployment_mode=mode,
        vip_lab_temporary_route_enabled=enabled,
    ))
    runtime.lab_vip_routes = {}
    return runtime


def test_lab_route_uses_kernel_next_hop_and_removes_only_owned_route(monkeypatch):
    runtime = _runtime()
    calls = []

    def fake_run(args, check=False, capture_output=False, text=False):
        calls.append(args)
        if args[:5] == ["ip", "-6", "route", "show", "exact"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:4] == ["ip", "-j", "-6", "route"]:
            return subprocess.CompletedProcess(
                args, 0, stdout=json.dumps([{"dev": "eth0", "gateway": "2001:db8::1"}]), stderr=""
            )
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    sid = b"s" * 16
    vip = "3191:9059:1edf:8053:5a34:18d1:8480:636d"
    runtime._install_lab_vip_route(sid, vip, "2001:4860::1")
    assert runtime.lab_vip_routes[sid] == (vip, "2001:db8::1", "eth0")
    assert ["ip", "-6", "route", "add", f"{vip}/128", "via", "2001:db8::1", "dev", "eth0"] in calls

    runtime._remove_lab_vip_route(sid)
    assert sid not in runtime.lab_vip_routes
    assert ["ip", "-6", "route", "del", f"{vip}/128", "via", "2001:db8::1", "dev", "eth0"] in calls


def test_lab_route_is_not_installed_when_disabled(monkeypatch):
    runtime = _runtime(enabled=False)
    def forbidden(*args, **kwargs):
        raise AssertionError("must not invoke route commands when disabled")
    monkeypatch.setattr(subprocess, "run", forbidden)
    runtime._install_lab_vip_route(b"s" * 16, "3191:9059:1edf:8053:5a34:18d1:8480:636d", "2001:4860::1")
    assert runtime.lab_vip_routes == {}


def test_lab_route_rejects_production_mode(monkeypatch):
    runtime = _runtime(mode="production", enabled=True)
    with pytest.raises(ValueError, match="forbidden outside lab mode"):
        runtime._install_lab_vip_route(b"s" * 16, "3191:9059:1edf:8053:5a34:18d1:8480:636d", "2001:4860::1")
