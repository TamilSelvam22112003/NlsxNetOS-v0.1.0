from pathlib import Path
import os
import yaml

CONFIG_DIR = Path(os.environ.get("NLSXNETOS_CONFIG_DIR", "/etc/nlsxnetos"))
STATE_DIR = Path("/var/lib/nlsxnetos")
LOG_DIR = Path("/var/log/nlsxnetos")


def load_yaml(name: str) -> dict:
    with (CONFIG_DIR / name).open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def ensure_layout():
    for p in (CONFIG_DIR, STATE_DIR, LOG_DIR):
        p.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(p, 0o750)
        except PermissionError:
            pass
    (STATE_DIR / "router-ca").mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(STATE_DIR / "router-ca", 0o750)
    except PermissionError:
        pass
