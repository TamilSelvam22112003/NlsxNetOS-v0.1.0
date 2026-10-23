import base64
import pytest

from nls.vip_table import VIPVerificationTable


def _record():
    cert = b"test-certificate-der"
    key_der = b"test-ed25519-spki-der"
    return {
        "router_id": "router-b",
        "originalIP": "2001:db8:2::1",
        "ed25519_public_key": base64.b64encode(b"e" * 32).decode(),
        "ed25519_public_key_spki_der_b64": base64.b64encode(key_der).decode(),
        "rsa_encryption_public_key": "test-rsa-public-key",
        "certificate_der_b64": base64.b64encode(cert).decode(),
        "wan_endpoints": ["[2001:db8:2::1]:4789"],
        "gateway_ips": ["2001:db8:2::1"],
        "prefixes": ["2001:db8:2::/64"],
        "certificate_serial": "1234",
        "status": "ACTIVE",
        "record_seq": 1,
    }, cert, key_der


def _stage(table, record, cert, key_der):
    table.stage(
        vip="fd42:4e4c:53::1234", router_id=record["router_id"],
        original_ip=record["originalIP"], certificate_der=cert,
        public_key_der=key_der, record_seq=1, session_id=b"s" * 16,
    )


def test_vip_promotes_only_when_peer_and_ca_records_match(tmp_path):
    table = VIPVerificationTable(state_path=tmp_path / "vip.json")
    record, cert, key_der = _record()
    _stage(table, record, cert, key_der)
    row = table.verify(
        session_id=b"s" * 16, vip="fd42:4e4c:53::1234",
        router_id=record["router_id"], original_ip=record["originalIP"],
        certificate_der=cert, public_key_der=key_der, record_seq=1,
        ca_record_verified=True, destination_signature_verified=True,
        destination_record=dict(record), router_ca_record=dict(record),
    )
    assert row["status"] == "VERIFIED"
    assert row["dest_router_ip_from_dest_router"] == record["originalIP"]
    assert row["dest_router_ip_from_router_ca"] == record["originalIP"]
    assert row["symmetric_key_from_dest_router"] is None
    assert row["key_establishment"] == "X25519-HKDF-SHA256"


def test_vip_rejects_peer_record_mismatch(tmp_path):
    table = VIPVerificationTable(state_path=tmp_path / "vip.json")
    record, cert, key_der = _record()
    _stage(table, record, cert, key_der)
    peer = dict(record, originalIP="2001:db8:99::1")
    with pytest.raises(ValueError, match="does not match Router-CA"):
        table.verify(
            session_id=b"s" * 16, vip="fd42:4e4c:53::1234",
            router_id=record["router_id"], original_ip=record["originalIP"],
            certificate_der=cert, public_key_der=key_der, record_seq=1,
            ca_record_verified=True, destination_signature_verified=True,
            destination_record=peer, router_ca_record=record,
        )
    assert table.get(b"s" * 16)["status"] == "PENDING"


def test_vip_rejects_missing_independent_record(tmp_path):
    table = VIPVerificationTable(state_path=tmp_path / "vip.json")
    record, cert, key_der = _record()
    _stage(table, record, cert, key_der)
    with pytest.raises(ValueError, match="both destination-router and Router-CA"):
        table.verify(
            session_id=b"s" * 16, vip="fd42:4e4c:53::1234",
            router_id=record["router_id"], original_ip=record["originalIP"],
            certificate_der=cert, public_key_der=key_der, record_seq=1,
            ca_record_verified=True, destination_signature_verified=True,
        )
