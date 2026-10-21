import time

import pytest

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
    assert entry["originalIP"] == "2001:db8::2"
    assert lsdb.get("fd00:4e4c:53:1::2")["router_id"] == "router-a"


def test_bootstrap_vip_is_pending_and_not_resolvable(tmp_path, monkeypatch):
    from nls import lsdb
    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    sid = b"\x01" * 16
    entry = lsdb.publish_bootstrap_vip(
        "2001:4860:1::10", "router-a", "2001:4860:1::1", "pub",
        session_id=sid, expires_at=time.time() + 5, record_seq=7,
    )
    assert entry["record_type"] == "bootstrap_vip"
    assert entry["state"] == "PENDING"
    assert entry["authenticated"] is False
    assert entry["source_token"] is None
    assert entry["originalIP"] == "2001:4860:1::1"
    assert lsdb.get("2001:4860:1::10")["router_id"] == "router-a"
    assert lsdb.resolve_original_ip("2001:4860:1::1") is None
    assert lsdb.get_by_router_id("router-a") == []


def test_authenticated_vip_updates_original_ip_lookup_and_is_session_scoped(tmp_path, monkeypatch):
    from nls import lsdb
    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    sid = b"\x02" * 16
    entry = lsdb.publish_authenticated_vip(
        "2001:4860:2::10", "router-b", "2001:4860:2::1", "pub",
        source_token="2001:4860:2::10", send_token="2001:4860:3::10",
        local_original_ip="2001:4860:3::1", session_id=sid,
        record_seq=9, expires_at=time.time() + 60,
    )
    assert entry["authenticated"] is True
    resolved = lsdb.resolve_original_ip("2001:4860:2::1")
    assert resolved["source_token"] == "2001:4860:2::10"
    assert lsdb.get_by_router_id("router-b")[0]["record_seq"] == 9
    assert lsdb.remove("2001:4860:2::10", session_id=b"\x03" * 16) is False
    assert lsdb.get("2001:4860:2::10") is not None
    assert lsdb.remove("2001:4860:2::10", session_id=sid) is True
    assert lsdb.resolve_original_ip("2001:4860:2::1") is None


def test_bootstrap_vip_expiry_and_collision_fail_closed(tmp_path, monkeypatch):
    from nls import lsdb
    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    sid = b"\x04" * 16
    address = "2001:4860:4::10"
    lsdb.publish_bootstrap_vip(
        address, "router-a", "2001:4860:4::1", "pub",
        session_id=sid, expires_at=time.time() + 5,
    )
    with pytest.raises(ValueError, match="collision"):
        lsdb.publish_bootstrap_vip(
            address, "router-b", "2001:4860:4::2", "pub2",
            session_id=b"\x05" * 16, expires_at=time.time() + 5,
        )
    assert lsdb.remove(address, session_id=sid)
    assert lsdb.get(address) is None


def test_original_ip_resolver_rejects_ambiguous_active_bindings(tmp_path, monkeypatch):
    from nls import lsdb
    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    expiry = time.time() + 60
    lsdb.publish_authenticated_vip(
        "2001:4860:5::10", "router-a", "2001:4860:5::1", "pub-a",
        source_token="2001:4860:5::10", session_id=b"\x06" * 16,
        expires_at=expiry,
    )
    with pytest.raises(ValueError, match="original IP already belongs to another router"):
        lsdb.publish_authenticated_vip(
            "2001:4860:5::11", "router-b", "2001:4860:5::1", "pub-b",
            source_token="2001:4860:5::11", session_id=b"\x07" * 16,
            expires_at=expiry,
        )

    # The local and peer directional rows for one session are allowed to refer
    # to the same router originalIP when the router identity is the same.
    lsdb.publish_authenticated_vip(
        "2001:4860:5::12", "router-a", "2001:4860:5::1", "pub-a",
        source_token="2001:4860:5::12", session_id=b"\x06" * 16,
        expires_at=expiry,
    )
