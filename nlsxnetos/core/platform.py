from pathlib import Path
def ubuntu_release():
    data={}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line: k,v=line.split("=",1); data[k]=v.strip('"')
    return data.get("VERSION_ID","") if data.get("ID")=="ubuntu" else ""
def supported(): return ubuntu_release() in {"22.04","24.04"}
