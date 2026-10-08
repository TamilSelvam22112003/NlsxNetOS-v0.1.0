from security.trust.router_ca.models import RouterCAEntry
def test_router_ca_entry():
    e=RouterCAEntry(1,"2409:4000::/22","jio"); e.validate(); assert e.label=="jio"