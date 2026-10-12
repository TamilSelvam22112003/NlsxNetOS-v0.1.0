from types import SimpleNamespace

from net import validation


def test_confined_frr_validation_fails_closed_without_vtysh(monkeypatch):
    monkeypatch.setattr(validation.shutil, "which", lambda name: "/usr/bin/vtysh" if name == "vtysh" else "/usr/bin/systemctl")
    monkeypatch.setattr(validation, "_nlsxnetos_confined", lambda: True)
    monkeypatch.setattr(
        validation.subprocess, "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("subprocess must not run inside the confined profile")),
    )

    ok, detail = validation.frr_validate()
    assert ok is False
    assert "unavailable inside" in detail
    assert "administrator shell" in detail


def test_service_state_reports_unavailable_inside_confinement(monkeypatch):
    monkeypatch.setattr(validation, "_nlsxnetos_confined", lambda: True)
    monkeypatch.setattr(
        validation.subprocess, "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("systemctl must not run inside the confined profile")),
    )
    assert "unavailable" in validation.service_state("frr")


def test_unconfined_frr_validation_executes_vtysh(monkeypatch):
    monkeypatch.setattr(validation.shutil, "which", lambda name: "/usr/bin/vtysh" if name == "vtysh" else "/usr/bin/systemctl")
    monkeypatch.setattr(validation, "_nlsxnetos_confined", lambda: False)
    monkeypatch.setattr(validation.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="FRR version", stderr=""))

    ok, detail = validation.frr_validate()
    assert ok is True
    assert detail == "FRR version"
