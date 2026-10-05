from pathlib import Path
def test_no_frr_owned_package_tree():
    p=Path(__file__).resolve().parents[2]/"packaging"/"deb"
    assert not (p/"etc"/"frr").exists() and not (p/"usr"/"lib"/"frr").exists()