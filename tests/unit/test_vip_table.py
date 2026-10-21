import time

import pytest

from nls import vip_table


def test_vip_reservation_is_pending_persistent_and_session_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(vip_table, "STATE_PATH", tmp_path / "vip-table.json")
    vip = "2001:db8:100::1"
    sid = b"\x01" * 16

    row = vip_table.reserve(
        vip, "router-a", "2001:db8:100::10", "public-key-a",
        session_id=sid, expires_at=time.time() + 30, record_seq=3,
    )

    assert row["vip"] == vip
    assert row["session_id"] == sid.hex()
    assert row["state"] == "PENDING"
    assert row["authenticated"] is False
    assert vip_table.get(vip)["original_ip"] == "2001:db8:100::10"
    assert vip_table.entries()[vip]["record_type"] == "vip_reservation"

    assert vip_table.remove(vip, session_id=b"\x02" * 16) is False
    assert vip_table.get(vip) is not None
    assert vip_table.remove(vip, session_id=sid) is True
    assert vip_table.get(vip) is None


def test_vip_table_rejects_collision_and_duplicate_session_lease(tmp_path, monkeypatch):
    monkeypatch.setattr(vip_table, "STATE_PATH", tmp_path / "vip-table.json")
    expiry = time.time() + 30
    vip_table.reserve(
        "2001:db8:101::1", "router-a", "2001:db8:101::10", "key-a",
        session_id="a1" * 16, expires_at=expiry,
    )

    with pytest.raises(ValueError, match="another handshake"):
        vip_table.reserve(
            "2001:db8:101::1", "router-b", "2001:db8:101::20", "key-b",
            session_id="b2" * 16, expires_at=expiry,
        )
    with pytest.raises(ValueError, match="another vIP"):
        vip_table.reserve(
            "2001:db8:101::2", "router-a", "2001:db8:101::10", "key-a",
            session_id="a1" * 16, expires_at=expiry,
        )


def test_vip_table_expiry_and_invalid_addresses_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(vip_table, "STATE_PATH", tmp_path / "vip-table.json")
    vip = "2001:db8:102::1"
    deadline = time.time() + 30
    vip_table.reserve(
        vip, "router-a", "2001:db8:102::10", "key-a",
        session_id="c3" * 16, expires_at=deadline,
    )

    assert vip_table.get(vip, now=deadline + 1) is None
    assert vip_table.entries(now=deadline + 1) == {}
    with pytest.raises(ValueError, match="IPv6 address"):
        vip_table.reserve(
            "not-an-ip", "router-a", "2001:db8:102::10", "key-a",
            session_id="d4" * 16, expires_at=time.time() + 30,
        )
    with pytest.raises(ValueError, match="expiry"):
        vip_table.reserve(
            vip, "router-a", "2001:db8:102::10", "key-a",
            session_id="e5" * 16, expires_at=time.time() - 1,
        )


def test_vip_reservation_is_idempotent_only_for_exact_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(vip_table, "STATE_PATH", tmp_path / "vip-table.json")
    vip = "2001:db8:103::1"
    expiry = time.time() + 30
    args = dict(
        session_id="f6" * 16, expires_at=expiry, record_seq=8,
    )
    first = vip_table.reserve(vip, "router-a", "2001:db8:103::10", "key-a", **args)
    same = vip_table.reserve(vip, "router-a", "2001:db8:103::10", "key-a", **args)
    assert same["session_id"] == first["session_id"]

    with pytest.raises(ValueError, match="another handshake"):
        vip_table.reserve(
            vip, "router-a", "2001:db8:103::11", "key-a", **args,
        )
