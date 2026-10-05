from .models import RouterCAEntry
from . import store
def list_entries():
    for e in store.load(): print(f"Router-CA {e.id} {e.prefix} {e.label}")
def add_entry(i,prefix,label,key=None): store.add(RouterCAEntry(i,prefix,label,key))
def remove_entry(i): store.remove(i)
def validate(): store.load(); print("Router-CA: valid")
