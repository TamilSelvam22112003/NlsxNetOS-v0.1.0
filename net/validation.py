from pathlib import Path
import shutil
import subprocess


def _nlsxnetos_confined() -> bool:
    """Fail closed when the AppArmor label cannot be inspected."""
    try:
        label = Path("/proc/self/attr/current").read_text(encoding="utf-8").strip().strip('"')
    except OSError:
        return True
    return label.split()[0] == "nlsxnetos"


def frr_validate():
    if not shutil.which("vtysh"):
        return False, "vtysh is not installed"

    # The NlsxNetOS AppArmor profile intentionally does not grant access to
    # FRR's administrative VTY configuration/socket. Do not broaden router
    # privileges just to run "show version"; verify daemon state instead.
    # The full vtysh check is available from an unconfined administrator shell
    # and is also exercised by tests/integration/test_frr.py.
    if _nlsxnetos_confined():
        state = service_state("frr")
        if state == "active":
            return True, "FRR service active; vtysh CLI probe skipped in NlsxNetOS confinement"
        return False, f"FRR service is {state}; vtysh CLI probe skipped in NlsxNetOS confinement"

    result = subprocess.run(["vtysh", "-c", "show version"], text=True, capture_output=True)
    return (True, result.stdout.strip()) if result.returncode == 0 else (False, (result.stderr or result.stdout).strip())


def service_state(name):
    if not shutil.which("systemctl"):
        return "unknown"
    result = subprocess.run(["systemctl", "is-active", name], text=True, capture_output=True)
    return result.stdout.strip() or "inactive"
