from dataclasses import dataclass,asdict
import ipaddress
@dataclass(frozen=True)
class RouterCAEntry:
    id:int; prefix:str; label:str; public_key:str|None=None
    def validate(self):
        ipaddress.ip_network(self.prefix,strict=False)
        if not 1<=self.id<=65535: raise ValueError("Router-CA id must be 1..65535")
        if not self.label or any(c.isspace() for c in self.label): raise ValueError("invalid label")
    def as_dict(self): return asdict(self)
