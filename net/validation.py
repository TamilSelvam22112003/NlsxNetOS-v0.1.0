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

    # The router AppArmor profile deliberately has no access to FRR's
    # administrative VTY config/socket or the system D-Bus. Never expand the
    # router daemon's privileges merely to run an administrative diagnostic.
    if _nlsxnetos_confined():
        return (
            False,
            "vtysh validation is unavailable inside NlsxNetOS AppArmor confinement; "
            "run 'systemctl is-active frr' and 'vtysh -c \"show version\"' from an administrator shell",
        )

    result = subprocess.run(["vtysh", "-c", "show version"], text=True, capture_output=True)
    return (True, result.stdout.strip()) if result.returncode == 0 else (False, (result.stderr or result.stdout).strip())


def service_state(name):
    if _nlsxnetos_confined():
        return "unavailable (NlsxNetOS AppArmor confinement)"
    if not shutil.which("systemctl"):
        return "unknown"
    result = subprocess.run(["systemctl", "is-active", name], text=True, capture_output=True)
    return result.stdout.strip() or "inactive"
