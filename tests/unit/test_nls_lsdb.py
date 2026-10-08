import time

def test_lsdb_expires_vip(tmp_path, monkeypatch):
    from nls import lsdb
    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    lsdb.upsert("fd00:4e4c:53:1::1", "router-a", "2001:db8::1", "pub", time.time() - 1)
    assert lsdb.get("fd00:4e4c:53:1::1") is None

def test_lsdb_stores_authenticated_binding(tmp_path, monkeypatch):
    from nls import lsdb
    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    entry=lsdb.upsert("fd00:4e4c:53:1::2", "router-a", "2001:db8::2", "pub", time.time() + 60)
    assert entry["original_ip"] == "2001:db8::2"
    assert lsdb.get("fd00:4e4c:53:1::2")["router_id"] == "router-a"
