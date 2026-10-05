import os
import shutil
import subprocess
import pytest

def test_vtysh():
    if not shutil.which("vtysh"):
        pytest.skip("FRR not installed")
    cmd = ["vtysh", "-c", "show version"] if os.geteuid() == 0 else ["sudo", "-n", "vtysh", "-c", "show version"]
    assert subprocess.run(cmd, capture_output=True).returncode == 0
