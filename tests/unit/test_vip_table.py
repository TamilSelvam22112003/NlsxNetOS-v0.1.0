"""Unit tests for the temporary vIP identity verification table."""
import base64
import json
import time

import pytest

from nls.vip_table import VIPVerificationTable


def candidate():
    return {
        "vip": "fd42:4e4c:53::1234",
        "router_id": "router-a",
        "original_ip": "2001:db8:1::1",
        "certificate_der": b"unit-test-certificate-der",
        "public_key_der": b"unit-test-ed25519-subject-public-key-info",
        "record_seq": 7,
        "session_id": b"session-00000001",
        "status": "ACTIVE",
    }


def stage(table, **overrides):
    fields = candidate()
    fields.update(overrides)
    return table.stage(**fields)


def verify(table, **overrides):
    fields = candidate()
    fields.update(overrides)
    # Simulate the independently verified Router Directory Record and the
    # peer-presented copy. The tests deliberately vary the caller's claims
    # while keeping the staged row immutable.
    cert_b64 = base64.b64encode(fields["certificate_der"]).decode("ascii")
    key_b64 = base64.b64encode(fields["public_key_der"]).decode("ascii")
    record = {
        "status": "ACTIVE",
        "router_id": fields["router_id"],
        "originalIP": fields["original_ip"],
        "ed25519_public_key": "ed25519-test-public-key",
        "ed25519_public_key_spki_der_b64": key_b64,
        "rsa_encryption_public_key": "rsa-test-public-key",
        "certificate_der_b64": cert_b64,
        "wan_endpoints": ["2001:db8:1::1"],
        "gateway_ips": [],
        "prefixes": [],
        "certificate_serial": "test-serial",
    }
    return table.verify(
        **{key: fields[key] for key in (
            "session_id", "vip", "router_id", "original_ip",
            "certificate_der", "public_key_der", "record_seq",
        )},
        ca_record_verified=True,
        destination_signature_verified=True,
        destination_record=dict(record),
        router_ca_record=dict(record),
    )

def test_stage_keeps_mapping_pending_and_separate_from_lsdb(tmp_path):
    table = VIPVerificationTable(tmp_path / "vip-verification.json")
    row = stage(table)
    assert row["status"] == "PENDING"
    assert row["vip"] == "fd42:4e4c:53::1234"
    assert row["original_ip"] == "2001:db8:1::1"
    assert base64.b64decode(row["certificate_der_b64"]) == candidate()["certificate_der"]
    assert base64.b64decode(row["public_key_der_b64"]) == candidate()["public_key_der"]
    persisted = json.loads((tmp_path / "vip-verification.json").read_text())
    assert persisted["_table_version"] == 1
    assert len(persisted["entries"]) == 1
    assert not table.is_verified(candidate()["session_id"])


def test_exact_ca_and_peer_match_promotes_to_verified(tmp_path):
    table = VIPVerificationTable(tmp_path / "vip-verification.json")
    stage(table)
    row = verify(table)
    assert row["status"] == "VERIFIED"
    assert row["verification"] == {
        "router_ca_record": True,
        "destination_router": True,
        "certificate_match": True,
        "public_key_match": True,
        "original_ip_match": True,
        "record_seq_match": True,
    }
    assert table.is_verified(candidate()["session_id"])


@pytest.mark.parametrize("field,value", [
    ("vip", "fd42:4e4c:53::9999"),
    ("router_id", "attacker"),
    ("original_ip", "2001:db8:ffff::1"),
    ("certificate_der", b"attacker-certificate"),
    ("public_key_der", b"attacker-public-key"),
    ("record_seq", 6),
])
def test_mismatched_details_never_promote(tmp_path, field, value):
    table = VIPVerificationTable(tmp_path / "vip-verification.json")
    stage(table)
    with pytest.raises(ValueError, match="do not match"):
        verify(table, **{field: value})
    assert not table.is_verified(candidate()["session_id"])


@pytest.mark.parametrize("flag", ["ca_record_verified", "destination_signature_verified"])
def test_both_trust_checks_are_required(tmp_path, flag):
    table = VIPVerificationTable(tmp_path / "vip-verification.json")
    stage(table)
    fields = candidate()
    with pytest.raises(ValueError, match="verification are required"):
        table.verify(
            session_id=fields["session_id"], vip=fields["vip"],
            router_id=fields["router_id"], original_ip=fields["original_ip"],
            certificate_der=fields["certificate_der"],
            public_key_der=fields["public_key_der"], record_seq=fields["record_seq"],
            ca_record_verified=(flag != "ca_record_verified"),
            destination_signature_verified=(flag != "destination_signature_verified"),
        )
    assert not table.is_verified(fields["session_id"])


def test_table_expires_and_cleans_rows(tmp_path):
    table = VIPVerificationTable(tmp_path / "vip-verification.json", ttl=2)
    fields = candidate()
    table.stage(**fields, expires_at=time.time() + 1)
    assert table.expire(now=time.time() + 2) == [fields["session_id"].hex()]
    assert table.get(fields["session_id"]) is None


def test_same_session_cannot_replace_identity_details(tmp_path):
    table = VIPVerificationTable(tmp_path / "vip-verification.json")
    stage(table)
    with pytest.raises(ValueError, match="conflicts"):
        stage(table, original_ip="2001:db8:2::2")


def test_non_active_ca_record_is_rejected(tmp_path):
    table = VIPVerificationTable(tmp_path / "vip-verification.json")
    with pytest.raises(ValueError, match="must be ACTIVE"):
        stage(table, status="REVOKED")


def test_router_scoped_tables_do_not_delete_each_others_rows(tmp_path):
    base = tmp_path / "vip-verification.json"
    router_a = VIPVerificationTable(base, router_id="router-a")
    router_b = VIPVerificationTable(base, router_id="router-b")
    assert router_a.state_path != router_b.state_path

    # A namespace lab can share the same filesystem and handshake ID across
    # multiple router processes. Each daemon must own an independent row.
    stage(router_a)
    stage(router_b)
    verify(router_a)
    assert router_a.is_verified(candidate()["session_id"])
    assert not router_b.is_verified(candidate()["session_id"])

    assert router_a.remove(candidate()["session_id"])
    assert router_b.get(candidate()["session_id"])["status"] == "PENDING"
