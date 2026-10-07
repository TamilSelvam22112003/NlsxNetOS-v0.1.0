from pathlib import Path
import os, ipaddress, yaml
from .models import RouterCAEntry
PATH = Path(os.environ.get("NLSXNETOS_ROUTER_CA_PATH", "/etc/nlsxnetos/router-ca.yaml"))
def _validate_entries(entries):
    entries=list(entries)
    for e in entries: e.validate()
    if len({e.id for e in entries}) != len(entries): raise ValueError("duplicate Router-CA id")
    active=[e for e in entries if e.nls_ready]
    checks={
        "public key":[e.public_key for e in active],
        "RSA encryption key":[e.encryption_public_key for e in active],
        "RSA signing key":[e.signing_public_key for e in active],
        "endpoint":[e.endpoint for e in active],
        "destination prefix":[str(ipaddress.ip_network(e.prefix, strict=False)) for e in active],
    }
    for label, values in checks.items():
        if len(values)!=len(set(values)): raise ValueError(f"duplicate active Router-CA {label}")
    return entries
def load():
    if not PATH.exists(): return []
    data=yaml.safe_load(PATH.read_text(encoding="utf-8")) or {}
    if not isinstance(data,dict): raise ValueError("Router-CA configuration must be a YAML mapping")
    return sorted(_validate_entries([RouterCAEntry(**x) for x in data.get("entries",[])]),key=lambda x:x.id)
def save(entries):
    entries=_validate_entries(entries); PATH.parent.mkdir(parents=True,exist_ok=True)
    tmp=PATH.with_suffix(".tmp"); tmp.write_text(yaml.safe_dump({"entries":[e.as_dict() for e in entries]},sort_keys=False),encoding="utf-8")
    os.chmod(tmp,0o640); tmp.replace(PATH)
    try:
        import grp; os.chown(PATH,-1,grp.getgrnam("nlsxnetos").gr_gid)
    except (KeyError,PermissionError): pass
def add(entry): save([e for e in load() if e.id!=entry.id]+[entry])
def remove(identifier): save([e for e in load() if e.id!=identifier])
def active_entries(): return [e for e in load() if e.nls_ready]
def lookup(destination):
    address=ipaddress.ip_address(destination); matches=[]
    for e in active_entries():
        n=ipaddress.ip_network(e.prefix,strict=False)
        if n.version==address.version and address in n: matches.append((n.prefixlen,e))
    return max(matches,key=lambda x:x[0])[1] if matches else None
def lookup_endpoint(address):
    target=ipaddress.ip_address(str(address))
    from nlsxnetos.nls.config import endpoint
    for e in active_entries():
        try: host,_=endpoint(e.endpoint)
        except ValueError: continue
        if ipaddress.ip_address(host)==target: return e
    return None
