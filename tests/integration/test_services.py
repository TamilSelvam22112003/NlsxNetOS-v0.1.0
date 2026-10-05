from pathlib import Path
def test_units():
    root=Path(__file__).resolve().parents[2]
    assert all((root/"systemd"/x).exists() for x in ("nlsxnetos.service","nls-router.service","nls-ca.service"))