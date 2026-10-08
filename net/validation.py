import shutil,subprocess
def frr_validate():
    if not shutil.which("vtysh"): return False,"vtysh is not installed"
    r=subprocess.run(["vtysh","-c","show version"],text=True,capture_output=True)
    return (True,r.stdout.strip()) if r.returncode==0 else (False,(r.stderr or r.stdout).strip())
def service_state(name):
    if not shutil.which("systemctl"): return "unknown"
    r=subprocess.run(["systemctl","is-active",name],text=True,capture_output=True)
    return r.stdout.strip() or "inactive"
