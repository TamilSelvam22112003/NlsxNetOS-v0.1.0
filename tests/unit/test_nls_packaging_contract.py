from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_cbor2_is_pinned_and_declared_for_runtime_package():
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    control = (ROOT / "packaging/deb/DEBIAN/control").read_text(encoding="utf-8")
    assert "cbor2==5.9.0" in requirements
    assert 'cbor2==5.9.0' in pyproject
    assert "python3-cbor2" in control


def test_nls_services_can_write_cache_rollback_and_identity_state():
    router = (ROOT / "config/systemd/nls-router.service").read_text(encoding="utf-8")
    client = (ROOT / "config/systemd/nls-ca-client.service").read_text(encoding="utf-8")
    for service in (router, client):
        assert "/var/lib/nlsxnetos/security" in service
        assert "/var/lib/nlsxnetos/rollback" in service
        assert "/var/lib/nlsxnetos/identity" in service
        assert "MemoryDenyWriteExecute=true" in service
        assert "SystemCallFilter=" in service
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in router
    assert "AmbientCapabilities=CAP_NET_ADMIN" in router
    assert "RuntimeDirectory=nlsxnetos" in router
    assert "/run/nlsxnetos" in router


def test_rollback_mark_tmpfiles_and_deb_lifecycle_are_wired():
    tmpfiles = (ROOT / "config/tmpfiles.d/nlsxnetos.conf").read_text(encoding="utf-8")
    build = (ROOT / "scripts/build/deb.sh").read_text(encoding="utf-8")
    postinst = (ROOT / "packaging/deb/DEBIAN/postinst").read_text(encoding="utf-8")
    prerm = (ROOT / "packaging/deb/DEBIAN/prerm").read_text(encoding="utf-8")
    postrm = (ROOT / "packaging/deb/DEBIAN/postrm").read_text(encoding="utf-8")
    conffiles = (ROOT / "packaging/deb/DEBIAN/conffiles").read_text(encoding="utf-8")
    apparmor = (ROOT / "config/apparmor/usr.bin.nlsxnetos").read_text(encoding="utf-8")
    assert "directory-rollback-mark.json 0600 nlsxnetos nlsxnetos" in tmpfiles
    assert "config/tmpfiles.d/nlsxnetos.conf" in build
    assert "systemd-tmpfiles --create" in postinst
    assert "systemctl disable --now nls-ca-client.service" in prerm
    assert "purge" in postrm and "/var/lib/nlsxnetos" in postrm
    assert "/etc/nlsxnetos/router-ca-client.yaml" in conffiles
    assert "/var/lib/nlsxnetos/rollback/** rw," in apparmor
