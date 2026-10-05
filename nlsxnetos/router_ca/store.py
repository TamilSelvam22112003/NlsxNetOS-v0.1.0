from pathlib import Path
import yaml
from .models import RouterCAEntry
PATH=Path("/etc/nlsxnetos/router-ca.yaml")
def load():
    if not PATH.exists(): return []
    data=yaml.safe_load(PATH.read_text(encoding="utf-8")) or {}
    out=[RouterCAEntry(**x) for x in data.get("entries",[])]
    for e in out: e.validate()
    return sorted(out,key=lambda x:x.id)
def save(entries):
    PATH.parent.mkdir(parents=True,exist_ok=True); tmp=PATH.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump({"entries":[e.as_dict() for e in entries]},sort_keys=False),encoding="utf-8"); tmp.replace(PATH)
def add(entry): entry.validate(); save([e for e in load() if e.id!=entry.id]+[entry])
def remove(identifier): save([e for e in load() if e.id!=identifier])
