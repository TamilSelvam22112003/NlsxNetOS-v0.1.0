import json
import time

import pytest

from services.router import config as router_config


def test_operator_route_rejects_default_and_overlaps():
    data = {"router": {"interfaces": {}, "nls_routes": []}}
    router_config.add_nls_route(data, "10.10.0.0/16", "router-a")
    with pytest.raises(ValueError, match="default routes"):
        router_config.add_nls_route(data, "0.0.0.0/0", "router-b")
    with pytest.raises(ValueError, match="overlaps"):
        router_config.add_nls_route(data, "10.10.1.0/24", "router-b")
    with pytest.raises(ValueError, match="overlaps"):
        router_config.add_nls_route(data, "10.10.0.0/16", "router-b")
    assert data["router"]["nls_routes"] == [
        {"prefix": "10.10.0.0/16", "router_id": "router-a"}
    ]


def test_operator_route_rejects_host_bits_and_invalid_router_id():
    data = {"router": {"interfaces": {}, "nls_routes": []}}
    with pytest.raises(ValueError):
        router_config.add_nls_route(data, "10.10.1.1/24", "router-a")
    with pytest.raises(ValueError):
        router_config.add_nls_route(data, "10.10.0.0/24", "bad router id")
    assert data["router"]["nls_routes"] == []


def test_remove_operator_route_is_exact():
    data = {"router": {"interfaces": {}, "nls_routes": []}}
    router_config.add_nls_route(data, "2001:db8:100::/48", "router-v6")
    assert router_config.remove_nls_route(data, "2001:db8:100::/48")
    assert not router_config.remove_nls_route(data, "2001:db8:100::/48")
    assert data["router"]["nls_routes"] == []


def test_daemon_uses_precompiled_longest_prefix_routes_until_refresh(monkeypatch):
    import threading

    from nls.daemon import NLSDaemon

    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon._operator_route_cache = {4: {}, 6: {}}
    daemon._operator_route_prefix_lengths = {4: (), 6: ()}
    daemon._operator_route_config_signature = None
    daemon._operator_route_refresh_at = 0.0
    daemon._operator_route_cache_lock = threading.RLock()
    route_rows = [
        {"prefix": "10.0.0.0/8", "router_id": "router-wide"},
        {"prefix": "10.1.0.0/16", "router_id": "router-specific"},
    ]
    calls = []

    def load_routes():
        calls.append(1)
        return list(route_rows)

    monkeypatch.setattr("nls.routing.operator_routes", load_routes)
    assert daemon._operator_route_for_destination("10.1.2.3") == "router-specific"
    assert daemon._operator_route_for_destination("10.2.3.4") == "router-wide"
    assert len(calls) == 1, "route config should not be read for every packet"
    compiled_before = daemon._operator_route_cache

    daemon._operator_route_refresh_at = 0.0
    assert daemon._operator_route_for_destination("10.2.3.4") == "router-wide"
    assert len(calls) == 2
    assert daemon._operator_route_cache is compiled_before, (
        "unchanged config should reuse the compiled longest-prefix index"
    )

    route_rows[:] = [{"prefix": "10.0.0.0/8", "router_id": "router-new"}]
    daemon._operator_route_refresh_at = 0.0
    assert daemon._operator_route_for_destination("10.1.2.3") == "router-new"
    assert len(calls) == 3, "route config should be polled after refresh deadline"


def test_vip_table_publishes_original_ip_only_after_authenticated_session(tmp_path, monkeypatch):
    import json
    from nls import lsdb

    state_path = tmp_path / "vip-lsdb.json"
    monkeypatch.setattr(lsdb, "STATE_PATH", state_path)
    future = time.time() + 120

    # A bootstrap reservation is not a route and is not authenticated LSDB state.
    reserved = lsdb.reserve(
        "2001:4860:1::1", "router-b", "2001:4860:2::1", "identity-b",
        source_token="2001:4860:1::2", session_id=b"R" * 16,
        expires_at=future, state="PENDING",
    )
    assert reserved["state"] == "PENDING"
    assert reserved["original_ip"] == "2001:4860:2::1"
    with pytest.raises(ValueError, match="only authenticated established sessions"):
        lsdb.publish_authenticated(
            "2001:4860:1::1", "router-b", "2001:4860:2::1", "identity-b",
            source_token="2001:4860:1::2", session_id=b"R" * 16,
            expires_at=future, state="PENDING",
        )

    # Only completed session acceptance publishes authenticated originalIP metadata.
    published = lsdb.publish_authenticated(
        "2001:4860:1::1", "router-b", "2001:4860:2::1", "identity-b",
        source_token="2001:4860:1::2", session_id=b"R" * 16,
        record_seq=4, expires_at=future,
    )
    assert published["authenticated"] is True
    assert published["state"] == "ESTABLISHED"
    assert lsdb.get("2001:4860:1::1")["original_ip"] == "2001:4860:2::1"
    assert lsdb.get_by_original_ip("2001:4860:2::1")[0]["router_id"] == "router-b"
    assert lsdb.get_by_source_token("2001:4860:1::2")[0]["session_id"] == (b"R" * 16).hex()

    raw = json.loads(state_path.read_text(encoding="utf-8"))
    assert raw["_table_version"] == lsdb.TABLE_VERSION
    assert raw["entries"]["2001:4860:1::1"]["original_ip"] == "2001:4860:2::1"
    # The LSDB is metadata, not a route manager.
    assert "routes" not in raw


def test_vip_table_rejects_collisions_and_session_stale_delete(tmp_path, monkeypatch):
    from nls import lsdb

    monkeypatch.setattr(lsdb, "STATE_PATH", tmp_path / "vip-lsdb.json")
    future = time.time() + 120
    first_sid, second_sid = b"A" * 16, b"B" * 16
    lsdb.publish_authenticated(
        "2001:4860:1::1", "router-b", "2001:4860:2::1", "identity-b",
        source_token="2001:4860:1::2", session_id=first_sid, expires_at=future,
    )
    with pytest.raises(ValueError, match="SourceToken already belongs"):
        lsdb.publish_authenticated(
            "2001:4860:3::1", "router-b", "2001:4860:2::1", "identity-b",
            source_token="2001:4860:1::2", session_id=second_sid, expires_at=future,
        )
    # Old-session teardown must not delete an entry already refreshed by a new session.
    lsdb.publish_authenticated(
        "2001:4860:1::1", "router-b", "2001:4860:2::1", "identity-b",
        source_token="2001:4860:1::2", session_id=second_sid, expires_at=future,
    )
    assert lsdb.remove("2001:4860:1::1", session_id=first_sid) is False
    assert lsdb.get("2001:4860:1::1")["session_id"] == second_sid.hex()


def test_vip_table_expires_records_and_fails_closed_on_corrupt_file(tmp_path, monkeypatch):
    from nls import lsdb

    state_path = tmp_path / "vip-lsdb.json"
    monkeypatch.setattr(lsdb, "STATE_PATH", state_path)
    lsdb.publish_authenticated(
        "2001:4860:1::1", "router-b", "2001:4860:2::1", "identity-b",
        source_token="2001:4860:1::2", session_id=b"X" * 16, expires_at=time.time() + 1,
    )
    assert lsdb.get("2001:4860:1::1") is not None
    # Expiration is explicit and does not invent kernel routes.
    assert lsdb.expire(now=time.time() + 2) == {}
    state_path.write_text("{malformed", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unreadable"):
        lsdb.entries()
