from pathlib import Path
import os
import yaml
from .models import RouterCAEntry

PATH = Path(os.environ.get("NLSXNETOS_ROUTER_CA_PATH", "/etc/nlsxnetos/router-ca.yaml"))


def load():
    if not PATH.exists():
        return []
    data = yaml.safe_load(PATH.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Router-CA configuration must be a YAML mapping")
    out = []
    for raw in data.get("entries", []):
        if not isinstance(raw, dict):
            raise ValueError("Router-CA entry must be a YAML mapping")
        out.append(RouterCAEntry(**raw))
    for entry in out:
        entry.validate()
    ids = [e.id for e in out]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate Router-CA id")
    active_entries = [e for e in out if e.nls_ready]
    active_keys = [e.public_key for e in active_entries]
    if len(active_keys) != len(set(active_keys)):
        raise ValueError("duplicate active Router-CA public key")
    active_rsa_keys = [e.encryption_public_key for e in active_entries]
    if len(active_rsa_keys) != len(set(active_rsa_keys)):
        raise ValueError("duplicate active Router-CA RSA encryption key")
    active_signing_keys = [e.signing_public_key for e in active_entries]
    if len(active_signing_keys) != len(set(active_signing_keys)):
        raise ValueError("duplicate active Router-CA RSA signing key")
    active_endpoints = [e.endpoint for e in active_entries]
    if len(active_endpoints) != len(set(active_endpoints)):
        raise ValueError("duplicate active Router-CA endpoint")
    import ipaddress
    active_prefixes = [str(ipaddress.ip_network(e.prefix, strict=False)) for e in active_entries]
    if len(active_prefixes) != len(set(active_prefixes)):
        raise ValueError("duplicate active Router-CA destination prefix")
    return sorted(out, key=lambda x: x.id)


def save(entries):
    entries = list(entries)
    for entry in entries:
        entry.validate()
    ids = [e.id for e in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate Router-CA id")
    active_entries = [e for e in entries if e.nls_ready]
    active_keys = [e.public_key for e in active_entries]
    if len(active_keys) != len(set(active_keys)):
        raise ValueError("duplicate active Router-CA public key")
    active_rsa_keys = [e.encryption_public_key for e in active_entries]
    if len(active_rsa_keys) != len(set(active_rsa_keys)):
        raise ValueError("duplicate active Router-CA RSA encryption key")
    active_endpoints = [e.endpoint for e in active_entries]
    if len(active_endpoints) != len(set(active_endpoints)):
        raise ValueError("duplicate active Router-CA endpoint")
    active_prefixes = [str(__import__("ipaddress").ip_network(e.prefix, strict=False)) for e in active_entries]
    if len(active_prefixes) != len(set(active_prefixes)):
        raise ValueError("duplicate active Router-CA destination prefix")
    PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PATH.with_suffix(".tmp")
    tmp.write_text(
        yaml.safe_dump({"entries": [e.as_dict() for e in entries]}, sort_keys=False),
        encoding="utf-8",
    )
    os.chmod(tmp, 0o640)
    tmp.replace(PATH)
    try:
        import grp
        os.chown(PATH, -1, grp.getgrnam("nlsxnetos").gr_gid)
    except (KeyError, PermissionError):
        pass


def add(entry):
    entry.validate()
    save([e for e in load() if e.id != entry.id] + [entry])


def remove(identifier):
    save([e for e in load() if e.id != identifier])


def active_entries():
    return [e for e in load() if e.nls_ready]


def lookup(destination):
    import ipaddress
    address = ipaddress.ip_address(destination)
    matches = []
    for entry in active_entries():
        network = ipaddress.ip_network(entry.prefix, strict=False)
        if network.version == address.version and address in network:
            matches.append((network.prefixlen, entry))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]

def lookup_endpoint(address):
    """Return the active router whose registered NLS endpoint matches address."""
    import ipaddress
    from nlsxnetos.nls.config import endpoint
    target = ipaddress.ip_address(str(address))
    for entry in active_entries():
        if not entry.endpoint:
            continue
        try:
            host, _port = endpoint(entry.endpoint)
        except ValueError:
            continue
        if ipaddress.ip_address(host) == target:
            return entry
    return None
