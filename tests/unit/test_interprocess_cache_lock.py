import subprocess
import sys
import time
from pathlib import Path


def test_router_ca_cache_lock_serializes_separate_processes(tmp_path):
    """The daemon and CA agent must not interleave cache/rollback-mark writes."""
    from nls.ca_client import _interprocess_cache_lock

    cache_path = tmp_path / "router-directory.json"
    started_path = tmp_path / "child-started"
    acquired_path = tmp_path / "child-acquired"
    settings = type("Settings", (), {"directory_file": cache_path})()

    child_code = r"""
import sys
from pathlib import Path
from types import SimpleNamespace
from nls.ca_client import _interprocess_cache_lock
cache = Path(sys.argv[1])
started = Path(sys.argv[2])
acquired = Path(sys.argv[3])
started.write_text("started", encoding="ascii")
with _interprocess_cache_lock(SimpleNamespace(directory_file=cache)):
    acquired.write_text("acquired", encoding="ascii")
"""
    with _interprocess_cache_lock(settings):
        child = subprocess.Popen(
            [sys.executable, "-c", child_code, str(cache_path), str(started_path), str(acquired_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not started_path.exists():
            time.sleep(0.01)
        assert started_path.exists(), "child process did not start its cache-lock attempt"
        time.sleep(0.1)
        assert not acquired_path.exists(), "child entered the cache transaction while parent held the lock"

    stdout, stderr = child.communicate(timeout=3)
    assert child.returncode == 0, f"child failed: stdout={stdout!r}; stderr={stderr!r}"
    assert acquired_path.read_text(encoding="ascii") == "acquired"
