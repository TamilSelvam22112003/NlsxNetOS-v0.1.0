import shutil,subprocess,pytest
def test_vtysh():
    if not shutil.which("vtysh"): pytest.skip("FRR not installed")
    assert subprocess.run(["vtysh","-c","show version"],capture_output=True).returncode==0