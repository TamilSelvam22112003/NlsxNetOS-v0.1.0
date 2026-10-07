from .models import RouterCAEntry
from . import store


def list_entries():
    for e in store.load():
        extra = f" endpoint={e.endpoint}" if e.endpoint else ""
        rsa = " rsa-encryption=configured" if e.encryption_public_key else ""
        key = " configured" if e.public_key else " trust-only"
        print(f"Router-CA {e.id} {e.prefix} {e.label}{extra}{rsa}{key}")


def add_entry(i, prefix, label, public_key=None, endpoint_value=None, encryption_public_key=None):
    entry = RouterCAEntry(i, prefix, label, public_key, endpoint_value, encryption_public_key)
    entry.validate()
    store.add(entry)
    if entry.nls_ready:
        from nlsxnetos.nls.activation import activate
        activate()


def remove_entry(i):
    store.remove(i)
    if not store.active_entries():
        from nlsxnetos.nls.activation import deactivate
        deactivate()


def validate():
    store.load()
    print("Router-CA: valid")
