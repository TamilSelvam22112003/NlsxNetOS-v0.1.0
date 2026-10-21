import time

import pytest


def test_lsdb_expires_vip(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    vip = "2001:4860:10::1"
    lsdb.publish_authenticated_vip(
        vip, "router-a", "2001:4860:10::2", "pub",
        source_token=vip, session_id=b"\x10" * 16,
        expires_at=time.time() + 60,
    )

    lsdb.expire(now=time.time() + 61)
    assert lsdb.get(vip) is None


def test_lsdb_stores_authenticated_binding(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    vip = "2001:4860:11::1"
    entry = lsdb.publish_authenticated_vip(
        vip, "router-a", "2001:4860:11::2", "pub",
        source_token=vip, session_id=b"\x11" * 16,
        expires_at=time.time() + 60,
    )
    assert entry["original_ip"] == "2001:4860:11::2"
    assert entry["originalIP"] == "2001:4860:11::2"
    assert entry["authenticated"] is True
    assert lsdb.get(vip)["router_id"] == "router-a"


def test_bootstrap_vip_is_pending_and_not_resolvable(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    sid = b"\x01" * 16
    vip = "2001:4860:1::10"
    entry = lsdb.publish_bootstrap_vip(
        vip, "router-a", "2001:4860:1::1", "pub",
        session_id=sid, expires_at=time.time() + 5, record_seq=7,
    )

    assert entry["record_type"] == "bootstrap_vip"
    assert entry["state"] == "PENDING"
    assert entry["authenticated"] is False
    assert entry["source_token"] is None
    assert entry["originalIP"] == "2001:4860:1::1"
    assert lsdb.get(vip)["router_id"] == "router-a"
    assert lsdb.resolve_original_ip("2001:4860:1::1") is None
    assert lsdb.get_by_original_ip("2001:4860:1::1") == []
    assert lsdb.get_by_router_id("router-a") == []


def test_authenticated_vip_updates_original_ip_lookup_and_is_session_scoped(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    sid = b"\x02" * 16
    vip = "2001:4860:2::10"
    entry = lsdb.publish_authenticated_vip(
        vip, "router-b", "2001:4860:2::1", "pub",
        source_token=vip, send_token="2001:4860:3::10",
        local_original_ip="2001:4860:3::1", session_id=sid,
        record_seq=9, expires_at=time.time() + 60,
    )

    assert entry["authenticated"] is True
    resolved = lsdb.resolve_original_ip("2001:4860:2::1")
    assert resolved["source_token"] == vip
    assert lsdb.get_by_router_id("router-b")[0]["record_seq"] == 9
    assert lsdb.remove(vip, session_id=b"\x03" * 16) is False
    assert lsdb.get(vip) is not None
    assert lsdb.remove(vip, session_id=sid) is True
    assert lsdb.resolve_original_ip("2001:4860:2::1") is None


def test_bootstrap_vip_collision_fails_closed(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    sid = b"\x04" * 16
    vip = "2001:4860:4::10"
    lsdb.publish_bootstrap_vip(
        vip, "router-a", "2001:4860:4::1", "pub",
        session_id=sid, expires_at=time.time() + 5,
    )
    with pytest.raises(ValueError, match="collision"):
        lsdb.publish_bootstrap_vip(
            vip, "router-b", "2001:4860:4::2", "pub2",
            session_id=b"\x05" * 16, expires_at=time.time() + 5,
        )
    assert lsdb.remove(vip, session_id=sid)
    assert lsdb.get(vip) is None


def test_original_ip_cannot_be_claimed_by_two_router_identities(tmp_path, monkeypatch):
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


def test_rekey_keeps_old_overlap_row_until_session_scoped_teardown(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    expiry = time.time() + 60
    original_ip = "2001:4860:8::1"
    old_sid, new_sid = b"\x08" * 16, b"\x0b" * 16
    old_vip, new_vip = "2001:4860:8::10", "2001:4860:8::11"
    lsdb.publish_authenticated_vip(
        old_vip, "router-a", original_ip, "pub-a",
        source_token=old_vip, session_id=old_sid,
        state="OVERLAP", expires_at=expiry,
    )
    lsdb.publish_authenticated_vip(
        new_vip, "router-a", original_ip, "pub-a",
        source_token=new_vip, session_id=new_sid,
        state="ESTABLISHED", expires_at=expiry,
    )

    assert len(lsdb.get_by_original_ip(original_ip)) == 2
    assert lsdb.remove(old_vip, session_id=old_sid) is True
    assert lsdb.get(old_vip) is None
    assert lsdb.get(new_vip)["session_id"] == new_sid.hex()

def test_original_ip_resolver_prefers_new_session_during_rekey_overlap(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    original_ip = "2001:4860:9::1"
    expiry = time.time() + 60
    lsdb.publish_authenticated_vip(
        "2001:4860:9::10", "router-a", original_ip, "pub-a",
        source_token="2001:4860:9::10", session_id=b"\x09" * 16,
        state="OVERLAP", expires_at=expiry,
    )
    newer = lsdb.publish_authenticated_vip(
        "2001:4860:9::11", "router-a", original_ip, "pub-a",
        source_token="2001:4860:9::11", session_id=b"\x0a" * 16,
        state="ESTABLISHED", expires_at=expiry,
    )

    resolved = lsdb.resolve_original_ip(original_ip)
    assert resolved["vip"] == newer["vip"]
    assert resolved["source_token"] == "2001:4860:9::11"


def test_bootstrap_vip_expiry_and_session_required(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    now = time.time()
    vip = "2001:4860:12::10"
    lsdb.publish_bootstrap_vip(
        vip, "router-a", "2001:4860:12::1", "pub",
        session_id=b"\x12" * 16, expires_at=now + 1,
    )
    lsdb.expire(now=now + 2)
    assert lsdb.get(vip) is None

    with pytest.raises(ValueError, match="session_id is required for bootstrap vIP"):
        lsdb.publish_bootstrap_vip(
            "2001:4860:12::11", "router-a", "2001:4860:12::1", "pub",
            session_id=None, expires_at=time.time() + 5,
        )
    with pytest.raises(ValueError, match="session_id is required for authenticated vIP publication"):
        lsdb.publish_authenticated_vip(
            "2001:4860:12::12", "router-a", "2001:4860:12::1", "pub",
            source_token="2001:4860:12::12", session_id=None,
            expires_at=time.time() + 5,
        )


def test_same_vip_cannot_be_reassigned_to_a_different_session(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    vip = "2001:4860:13::10"
    expiry = time.time() + 60
    lsdb.publish_authenticated_vip(
        vip, "router-a", "2001:4860:13::1", "pub",
        source_token=vip, session_id=b"\x13" * 16, expires_at=expiry,
    )
    with pytest.raises(ValueError, match="vIP already belongs to another router/session"):
        lsdb.publish_authenticated_vip(
            vip, "router-a", "2001:4860:13::1", "pub",
            source_token=vip, session_id=b"\x14" * 16, expires_at=expiry,
        )
