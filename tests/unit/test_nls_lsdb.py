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


def test_authenticated_binding_cannot_change_within_same_session(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    vip = "2001:4860:14::10"
    sid = b"\x14" * 16
    expiry = time.time() + 60
    lsdb.publish_authenticated_vip(
        vip, "router-a", "2001:4860:14::1", "pub-a",
        source_token=vip, session_id=sid, expires_at=expiry,
    )
    with pytest.raises(ValueError, match="authenticated vIP binding is immutable"):
        lsdb.publish_authenticated_vip(
            vip, "router-a", "2001:4860:14::2", "pub-a",
            source_token=vip, session_id=sid, expires_at=expiry,
        )


def test_bootstrap_original_ip_cannot_be_reserved_for_two_router_identities(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    expiry = time.time() + 60
    lsdb.publish_bootstrap_vip(
        "2001:4860:15::10", "router-a", "2001:4860:15::1", "pub-a",
        session_id=b"\x15" * 16, expires_at=expiry,
    )
    with pytest.raises(ValueError, match="original IP already belongs to another router"):
        lsdb.publish_bootstrap_vip(
            "2001:4860:15::11", "router-b", "2001:4860:15::1", "pub-b",
            session_id=b"\x16" * 16, expires_at=expiry,
        )


def test_export_records_excludes_pending_and_exports_authenticated_records(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    now = time.time()
    lsdb.publish_bootstrap_vip(
        "2001:db8:100::1", "router-a", "2001:db8:100::10", "pub-a",
        session_id=b"\x21" * 16, expires_at=now + 60,
    )
    lsdb.publish_authenticated_vip(
        "2001:db8:100::2", "router-a", "2001:db8:100::10", "pub-a",
        source_token="2001:db8:100::2", session_id=b"\x22" * 16,
        record_seq=7, expires_at=now + 60,
    )
    records = lsdb.export_records(now=now)
    assert len(records) == 1
    assert records[0]["record_type"] == "nls_vip_binding"
    assert records[0]["original_ip"] == "2001:db8:100::10"
    assert records[0]["record_seq"] == 7


def test_import_record_requires_authenticated_channel_identity_and_valid_schema(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    now = time.time()
    record = {
        "record_version": 1, "record_type": "nls_vip_binding",
        "vip": "2001:db8:101::1", "original_ip": "2001:db8:101::10",
        "router_id": "router-a", "identity_public_key": "pub-a",
        "source_token": "2001:db8:101::1", "session_id": "22" * 16,
        "record_seq": 3, "state": "ESTABLISHED", "expires_at": int(now + 60),
    }
    with pytest.raises(ValueError, match="does not match authenticated peer"):
        lsdb.import_record(record, authenticated_router_id="router-b", now=now)
    imported = lsdb.import_record(record, authenticated_router_id="router-a", now=now)
    assert imported["authenticated"] is True
    assert lsdb.resolve_original_ip("2001:db8:101::10", authenticated_only=True)["vip"] == record["vip"]
    with pytest.raises(ValueError, match="fields invalid"):
        lsdb.import_record({**record, "untrusted": True}, authenticated_router_id="router-a", now=now)


def test_withdrawal_is_session_scoped_and_cannot_remove_rekeyed_binding(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    now = time.time()
    old_sid, new_sid = b"\x23" * 16, b"\x24" * 16
    old_vip, new_vip = "2001:db8:102::1", "2001:db8:102::2"
    original = "2001:db8:102::10"
    lsdb.publish_authenticated_vip(
        old_vip, "router-a", original, "pub-a", source_token=old_vip,
        session_id=old_sid, state="OVERLAP", expires_at=now + 60,
    )
    withdrawal = lsdb.withdrawal_record(old_vip, session_id=old_sid, record_seq=8)
    lsdb.publish_authenticated_vip(
        new_vip, "router-a", original, "pub-a", source_token=new_vip,
        session_id=new_sid, state="ESTABLISHED", expires_at=now + 60,
    )
    assert withdrawal is not None
    assert lsdb.apply_withdrawal(withdrawal, authenticated_router_id="router-a") is True
    assert lsdb.get(old_vip) is None
    assert lsdb.apply_withdrawal(withdrawal, authenticated_router_id="router-a") is True
    assert lsdb.get(new_vip) is not None
    assert lsdb.resolve_original_ip(original)["vip"] == new_vip


def test_import_rejects_expired_or_pending_lsdb_record(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    record = {
        "record_version": 1, "record_type": "nls_vip_binding",
        "vip": "2001:db8:103::1", "original_ip": "2001:db8:103::10",
        "router_id": "router-a", "identity_public_key": "pub-a",
        "source_token": "2001:db8:103::1", "session_id": "25" * 16,
        "record_seq": 1, "state": "PENDING", "expires_at": int(time.time() + 60),
    }
    with pytest.raises(ValueError, match="only established"):
        lsdb.import_record(record, authenticated_router_id="router-a")
    record["state"] = "ESTABLISHED"
    record["expires_at"] = int(time.time() - 1)
    with pytest.raises(ValueError, match="expired"):
        lsdb.import_record(record, authenticated_router_id="router-a")


def test_mirrored_directional_source_token_row_is_allowed_for_same_session(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    expiry = time.time() + 60
    sid = b"\x31" * 16
    token = "2001:db8:104::1"
    original = "2001:db8:104::10"
    lsdb.publish_authenticated_vip(
        token, "router-b", original, "pub-b", source_token=token,
        session_id=sid, expires_at=expiry,
    )
    # The same sender/direction can be represented by a receiving-token row
    # at the sender and a sending-token row at its peer.
    mirror = lsdb.publish_authenticated_vip(
        "2001:db8:104::2", "router-a", original, "pub-a",
        source_token=token, session_id=sid, expires_at=expiry,
    )
    assert mirror["authenticated"] is True
    assert len(lsdb.get_by_source_token(token)) == 2


def test_source_token_collision_still_rejects_different_session_or_identity(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    expiry = time.time() + 60
    token = "2001:db8:105::1"
    lsdb.publish_authenticated_vip(
        token, "router-a", "2001:db8:105::10", "pub-a",
        source_token=token, session_id=b"\x32" * 16, expires_at=expiry,
    )
    with pytest.raises(ValueError, match="SourceToken already belongs"):
        lsdb.publish_authenticated_vip(
            "2001:db8:105::2", "router-a", "2001:db8:105::10", "pub-a",
            source_token=token, session_id=b"\x33" * 16, expires_at=expiry,
        )
    with pytest.raises(ValueError, match="SourceToken already belongs"):
        lsdb.publish_authenticated_vip(
            "2001:db8:105::3", "router-b", "2001:db8:105::10", "pub-b",
            source_token=token, session_id=b"\x32" * 16, expires_at=expiry,
        )


def test_mirrored_original_ip_can_be_viewed_by_both_authenticated_session_peers(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    expiry = time.time() + 60
    sid = b"\\x34" * 16
    original = "2001:db8:106::10"
    lsdb.publish_authenticated_vip(
        "2001:db8:106::1", "router-a", original, "pub-a",
        source_token="2001:db8:106::1", session_id=sid, expires_at=expiry,
    )
    mirror = lsdb.publish_authenticated_vip(
        "2001:db8:106::2", "router-b", original, "pub-b",
        source_token="2001:db8:106::2", session_id=sid, expires_at=expiry,
    )
    assert mirror["router_id"] == "router-b"
    rows = lsdb.resolve_original_ip(original)
    assert {row["router_id"] for row in rows} == {"router-a", "router-b"}


def test_original_ip_collision_from_unrelated_session_remains_rejected(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "lsdb.json")
    expiry = time.time() + 60
    original = "2001:db8:107::10"
    lsdb.publish_authenticated_vip(
        "2001:db8:107::1", "router-a", original, "pub-a",
        source_token="2001:db8:107::1", session_id=b"\\x35" * 16, expires_at=expiry,
    )
    with pytest.raises(ValueError, match="original IP already belongs to another router"):
        lsdb.publish_authenticated_vip(
            "2001:db8:107::2", "router-b", original, "pub-b",
            source_token="2001:db8:107::2", session_id=b"\\x36" * 16, expires_at=expiry,
        )
