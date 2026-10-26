import base64
import hashlib

import pytest

from nls.trust_table import TrustTable


def verified_vip_row():
    cert = b"test-certificate-der"
    raw_key = b"test-ed25519-raw-public-key"
    spki = b"test-ed25519-spki-der"
    cert_b64 = base64.b64encode(cert).decode("ascii")
    raw_key_b64 = base64.b64encode(raw_key).decode("ascii")
    return {
        "session_id": "session-001",
        "vip": "fd00::1234",
        "router_id": "router-d",
        "original_ip": "2001:db8::d",
        "certificate_sha256": hashlib.sha256(cert).hexdigest(),
        "public_key_sha256": hashlib.sha256(spki).hexdigest(),
        "public_key_der_b64": base64.b64encode(spki).decode("ascii"),
        "record_seq": 7,
        "status": "VERIFIED",
        "dest_router_ip": "2001:db8::d",
        "dest_router_ip_from_router_ca": "2001:db8::d",
        "dest_router_certificate": cert_b64,
        "dest_router_certificate_from_router_ca": cert_b64,
        "dest_router_public_key": raw_key_b64,
        "dest_router_public_key_from_router_ca": raw_key_b64,
        "dest_router_wan_endpoints": ["[2001:db8::d]:4789"],
        "dest_router_wan_endpoints_from_router_ca": ["[2001:db8::d]:4789"],
        "dest_router_gateway_ips": ["2001:db8::1"],
        "dest_router_gateway_ips_from_router_ca": ["2001:db8::1"],
        "dest_router_prefixes": ["2001:db8:1::/64"],
        "dest_router_prefixes_from_router_ca": ["2001:db8:1::/64"],
        "dest_router_certificate_serial": "serial-123",
        "dest_router_certificate_serial_from_router_ca": "serial-123",
        "verification": {
            "router_ca_record": True,
            "destination_router": True,
            "certificate_match": True,
            "public_key_match": True,
            "original_ip_match": True,
            "record_seq_match": True,
        },
    }



def _write_trust_row_in_process(args):
    state_path, index = args
    table = TrustTable(state_path)
    row = verified_vip_row()
    row["session_id"] = f"process-session-{index:03d}"
    row["vip"] = f"fd00::{index + 1:x}"
    table.record_verified_vip(row)
    return row["session_id"]


def test_trust_table_only_promotes_exactly_cross_verified_vip(tmp_path):
    table = TrustTable(tmp_path / "trust.json")
    row = table.record_verified_vip(verified_vip_row())

    assert row["state"] == "TRUSTED"
    assert row["router_id"] == "router-d"
    assert row["original_ip"] == "2001:db8::d"
    assert table.is_trusted("session-001")
    # Trust table stores fingerprints and identity metadata, not raw certificate/key.
    persisted = (tmp_path / "trust.json").read_text()
    assert "test-certificate-der" not in persisted
    assert "test-ed25519-raw-public-key" not in persisted


@pytest.mark.parametrize("field,value", [
    ("dest_router_ip_from_router_ca", "2001:db8::bad"),
    ("dest_router_certificate_from_router_ca", "different-certificate"),
    ("dest_router_public_key_from_router_ca", "different-key"),
    ("dest_router_wan_endpoints_from_router_ca", ["[2001:db8::bad]:4789"]),
    ("dest_router_gateway_ips_from_router_ca", ["2001:db8::bad"]),
    ("dest_router_prefixes_from_router_ca", ["2001:db8:bad::/64"]),
    ("dest_router_certificate_serial_from_router_ca", "serial-bad"),
])
def test_trust_table_rejects_vip_vs_ca_mismatch(tmp_path, field, value):
    row = verified_vip_row()
    row[field] = value
    table = TrustTable(tmp_path / "trust.json")

    with pytest.raises(ValueError, match="differ"):
        table.record_verified_vip(row)

    assert not table.is_trusted("session-001")


def test_trust_table_rejects_unverified_vip_row(tmp_path):
    row = verified_vip_row()
    row["verification"]["destination_router"] = False
    table = TrustTable(tmp_path / "trust.json")

    with pytest.raises(ValueError, match="cross-verification"):
        table.record_verified_vip(row)


def test_trust_table_removal_is_session_scoped(tmp_path):
    table = TrustTable(tmp_path / "trust.json")
    table.record_verified_vip(verified_vip_row())
    newer = verified_vip_row()
    newer["session_id"] = "session-002"
    newer["vip"] = "fd00::5678"
    table.record_verified_vip(newer)

    assert table.remove("session-001")
    assert not table.is_trusted("session-001")
    assert table.is_trusted("session-002")


def test_trust_table_expiry_removes_authorization(tmp_path):
    table = TrustTable(tmp_path / "trust.json")
    row = table.record_verified_vip(verified_vip_row(), session_ttl=1.0)
    assert table.is_trusted("session-001")

    expired = table.expire(now=row["expires_at"] + 1)

    assert expired == ["session-001"]
    assert not table.is_trusted("session-001")

def test_trust_table_observes_external_replacement_immediately(tmp_path):
    import json

    path = tmp_path / "trust.json"
    table = TrustTable(path)
    table.record_verified_vip(verified_vip_row())
    payload = json.loads(path.read_text())
    payload["entries"]["session-001"]["state"] = "REVOKED"
    path.write_text(json.dumps(payload))

    # Reads must not serve a stale in-memory authorization after external revoke.
    assert table.get("session-001")["state"] == "REVOKED"
    assert not table.is_trusted("session-001")


def test_trust_table_fails_closed_on_invalid_json_or_schema(tmp_path):
    path = tmp_path / "trust.json"
    table = TrustTable(path)

    path.write_text("{not-json")
    with pytest.raises(RuntimeError, match="unreadable"):
        table.get("session-001")

    path.write_text('{"_table_version": 999, "entries": {}}')
    with pytest.raises(RuntimeError, match="schema is invalid"):
        table.get("session-001")


def test_trust_table_lazy_expiry_removes_row_during_lookup(tmp_path):
    import json
    import time

    path = tmp_path / "trust.json"
    table = TrustTable(path)
    table.record_verified_vip(verified_vip_row())
    payload = json.loads(path.read_text())
    payload["entries"]["session-001"]["expires_at"] = time.time() - 1
    path.write_text(json.dumps(payload))

    assert table.get("session-001") is None
    assert "session-001" not in json.loads(path.read_text())["entries"]


def test_trust_table_restart_recovers_persisted_session(tmp_path):
    path = tmp_path / "trust.json"
    first = TrustTable(path)
    first.record_verified_vip(verified_vip_row())

    restarted = TrustTable(path)
    assert restarted.is_trusted("session-001")
    assert restarted.get("session-001")["router_id"] == "router-d"


def test_trust_table_concurrent_threaded_writes_preserve_all_sessions(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    path = tmp_path / "trust.json"
    table = TrustTable(path)

    def write(index):
        row = verified_vip_row()
        row["session_id"] = f"session-{index:03d}"
        row["vip"] = f"fd00::{index + 1:x}"
        return table.record_verified_vip(row)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(1, 33)))

    rows = table.entries()
    assert len(rows) == 32
    assert all(row["state"] == "TRUSTED" for row in rows.values())


def test_trust_table_state_locks_do_not_deadlock_when_paths_are_nested_in_reverse_order(tmp_path):
    import threading

    first = TrustTable(tmp_path / "first.json")
    second = TrustTable(tmp_path / "second.json")
    barrier = threading.Barrier(2)
    failures = []

    def nested(outer, inner):
        try:
            with outer._state_lock():
                barrier.wait(timeout=3)
                with inner._state_lock():
                    pass
        except Exception as exc:
            failures.append(exc)

    a = threading.Thread(target=nested, args=(first, second), daemon=True)
    b = threading.Thread(target=nested, args=(second, first), daemon=True)
    a.start()
    b.start()
    a.join(timeout=5)
    b.join(timeout=5)

    assert not a.is_alive() and not b.is_alive(), "cross-path lock acquisition deadlocked"
    assert failures == []

def test_trust_table_concurrent_process_writes_preserve_all_sessions(tmp_path):
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor

    path = str(tmp_path / "trust.json")
    context = multiprocessing.get_context("fork")
    tasks = [(path, index) for index in range(1, 25)]

    with ProcessPoolExecutor(max_workers=6, mp_context=context) as pool:
        written = list(pool.map(_write_trust_row_in_process, tasks))

    assert len(written) == 24
    assert len(set(written)) == 24
    rows = TrustTable(path).entries()
    assert len(rows) == 24
    assert set(rows) == set(written)
    assert all(row["state"] == "TRUSTED" for row in rows.values())



def test_trust_table_nested_locks_are_scoped_to_each_state_path(tmp_path, monkeypatch):
    import fcntl
    import nls.trust_table as trust_table_module

    first = TrustTable(tmp_path / "first.json")
    second = TrustTable(tmp_path / "second.json")
    acquired = []
    real_flock = fcntl.flock

    def observe_flock(fd, operation):
        if operation == fcntl.LOCK_EX:
            acquired.append(os.fstat(fd).st_ino)
        return real_flock(fd, operation)

    import os
    monkeypatch.setattr(trust_table_module.fcntl, "flock", observe_flock)

    with first._state_lock():
        with second._state_lock():
            pass

    assert len(acquired) == 2
    assert len(set(acquired)) == 2
