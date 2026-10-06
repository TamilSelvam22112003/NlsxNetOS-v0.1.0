from pathlib import Path
import yaml
from .models import RouterCAEntry

PATH = Path("/etc/nlsxnetos/router-ca.yaml")


def load():
    if not PATH.exists():
        return []
    data = yaml.safe_load(PATH.read_text(encoding="utf-8")) or {}
    out = []
    for raw in data.get("entries", []):
        # Backward compatible with v0.1.0 trust-only entries.
        out.append(RouterCAEntry(**raw))
    for entry in out:
        entry.validate()
    return sorted(out, key=lambda x: x.id)


def save(entries):
    PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PATH.with_suffix(".tmp")
    tmp.write_text(
        yaml.safe_dump({"entries": [e.as_dict() for e in entries]}, sort_keys=False),
        encoding="utf-8",
    )
    tmp.replace(PATH)


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
