import time


def test_vip_table_records_both_identity_sources(tmp_path, monkeypatch):
    from nls import vip_table

    monkeypatch.setattr(vip_table, "STATE_PATH", tmp_path / "vip-table.json")
    entry = vip_table.upsert(
        "fd00:4e4c:53:1::1", "router-b", "2001:db8::2", "ed25519-b",
        time.time() + 60,
        router_ca_details={"router_ca_id": 2, "endpoint": "[2001:db8::2]:4789"},
        router_details={"router_ca_id": 2, "endpoint": "[2001:db8::2]:4789"},
    )
    assert entry["router_ca_details"] == entry["router_details"]


def test_trust_table_only_retains_cross_verified_detail_records(tmp_path, monkeypatch):
    from nls import trust_table

    monkeypatch.setattr(trust_table, "STATE_PATH", tmp_path / "trust-table.json")
    ca_record = {"router_ca_id": 2, "public_key": "ed25519-b"}
    peer_record = {"router_ca_id": 2, "public_key": "ed25519-b"}
    trust_table.upsert("router-b", ca_record, peer_record, time.time() + 60)
    assert trust_table.get("router-b")["router_ca_details"] == ca_record
    assert trust_table.get("router-b")["router_details"] == peer_record
