from types import SimpleNamespace

from net import validation


def test_confined_frr_validation_uses_service_state_without_vtysh(monkeypatch):
    monkeypatch.setattr(validation.shutil, "which", lambda name: "/usr/bin/vtysh" if name == "vtysh" else "/usr/bin/systemctl")
    monkeypatch.setattr(validation, "_nlsxnetos_confined", lambda: True)
    monkeypatch.setattr(validation, "service_state", lambda name: "active")
    monkeypatch.setattr(
        validation.subprocess, "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("vtysh must not run inside the confined profile")),
    )

    ok, detail = validation.frr_validate()
    assert ok is True
    assert "FRR service active" in detail
    assert "skipped" in detail


def test_confined_frr_validation_fails_if_service_is_not_active(monkeypatch):
    monkeypatch.setattr(validation.shutil, "which", lambda name: "/usr/bin/vtysh" if name == "vtysh" else "/usr/bin/systemctl")
    monkeypatch.setattr(validation, "_nlsxnetos_confined", lambda: True)
    monkeypatch.setattr(validation, "service_state", lambda name: "inactive")

    ok, detail = validation.frr_validate()
    assert ok is False
    assert "inactive" in detail


def test_unconfined_frr_validation_executes_vtysh(monkeypatch):
    monkeypatch.setattr(validation.shutil, "which", lambda name: "/usr/bin/vtysh" if name == "vtysh" else "/usr/bin/systemctl")
    monkeypatch.setattr(validation, "_nlsxnetos_confined", lambda: False)
    monkeypatch.setattr(validation.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="FRR version", stderr=""))

    ok, detail = validation.frr_validate()
    assert ok is True
    assert detail == "FRR version"
