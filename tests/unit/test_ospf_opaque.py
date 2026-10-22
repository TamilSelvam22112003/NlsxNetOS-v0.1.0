import ipaddress
import json
import socket
import struct
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nls.ospf_opaque import (
    FRROSPFv2OpaqueAdapter,
    OSPFAPIError,
    decode_record,
    encode_record,
    pack_api_message,
    unpack_api_header,
)


def _record(**overrides):
    value = {
        "record_version": 1,
        "record_type": "nls_vip_binding",
        "router_id": "192.0.2.1",
        "original_ip": "2001:db8::1",
        "vip": "2001:db8:1::1",
        "source_token": "2001:db8:2::1",
        "session_id": "session-01",
        "record_seq": 1,
        "state": "ESTABLISHED",
        "expires_at": time.time() + 120,
        "key_id": "router-key-01",
    }
    value.update(overrides)
    return value


def _signer():
    private_key = Ed25519PrivateKey.generate()

    def verify(router_id, key_id, data, signature):
        if router_id != "192.0.2.1" or key_id != "router-key-01":
            return False
        try:
            private_key.public_key().verify(signature, data)
            return True
        except Exception:
            return False

    return private_key, lambda data: private_key.sign(data), verify


def test_signed_record_round_trip_and_canonical_addresses():
    _, sign, verify = _signer()
    payload = encode_record(_record(original_ip="2001:0db8:0:0::1"), sign)
    result = decode_record(payload, verify, advertising_router="192.0.2.1")
    assert result["original_ip"] == "2001:db8::1"
    assert result["record_seq"] == 1
    assert result["state"] == "ESTABLISHED"


@pytest.mark.parametrize(
    "overrides",
    [
        {"record_version": 2},
        {"record_version": True},
        {"record_type": "other"},
        {"router_id": "not-an-ip"},
        {"original_ip": "10.0.0.1"},
        {"record_seq": True},
        {"record_seq": 0},
        {"state": "PENDING"},
        {"state": []},
        {"key_id": ""},
        {"expires_at": time.time() - 1},
        {"expires_at": time.time() + 3600},
        {"expires_at": float("nan")},
        {"unexpected": "field"},
    ],
)
def test_record_schema_and_policy_reject_invalid_values(overrides):
    _, sign, _ = _signer()
    with pytest.raises((ValueError, TypeError)):
        encode_record(_record(**overrides), sign)


def test_wrong_advertising_router_is_rejected():
    _, sign, verify = _signer()
    payload = encode_record(_record(), sign)
    with pytest.raises(ValueError, match="advertising router"):
        decode_record(payload, verify, advertising_router="192.0.2.2")


def test_signature_tampering_is_rejected():
    _, sign, verify = _signer()
    envelope = json.loads(encode_record(_record(), sign))
    envelope["original_ip"] = "2001:db8::bad"
    with pytest.raises(ValueError, match="signature"):
        decode_record(json.dumps(envelope).encode(), verify, advertising_router="192.0.2.1")


def test_unknown_payload_fields_are_rejected():
    _, sign, verify = _signer()
    envelope = json.loads(encode_record(_record(), sign))
    envelope["kernel_route"] = "2001:db8::/64"
    with pytest.raises(ValueError, match="field set"):
        decode_record(json.dumps(envelope).encode(), verify, advertising_router="192.0.2.1")


def test_bad_signature_encoding_and_length_are_rejected():
    _, sign, verify = _signer()
    envelope = json.loads(encode_record(_record(), sign))
    envelope["signature"] = "c2hvcnQ="
    with pytest.raises(ValueError, match="signature length"):
        decode_record(json.dumps(envelope).encode(), verify, advertising_router="192.0.2.1")


def test_api_header_framing_round_trip():
    frame = pack_api_message(5, 7, b"payload")
    version, message_type, length, sequence = unpack_api_header(frame[:8])
    assert (version, message_type, length, sequence) == (1, 5, 7, 7)
    assert frame[8:] == b"payload"


def test_api_header_rejects_unknown_version_and_bad_size():
    with pytest.raises(ValueError, match="header size"):
        unpack_api_header(b"short!!")
    with pytest.raises(OSPFAPIError, match="version"):
        unpack_api_header(bytes([2, 5, 0, 0, 0, 0, 0, 1]))


def test_adapter_refuses_non_loopback_api_endpoint():
    with pytest.raises(ValueError, match="loopback"):
        FRROSPFv2OpaqueAdapter(host="192.0.2.10")


def test_adapter_will_not_originate_before_ready_registration():
    adapter = FRROSPFv2OpaqueAdapter()
    with pytest.raises(OSPFAPIError, match="registered and ready"):
        adapter.originate(1, b"signed")


def _lsa_notification(message_type, payload=b"", *, lsa_type=10, adv_router="192.0.2.1",
                      area_id="0.0.0.0", opaque_type=250, opaque_id=1):
    area = int(ipaddress.IPv4Address(area_id))
    adv = int(ipaddress.IPv4Address(adv_router))
    lsa_id = (opaque_type << 24) | opaque_id
    lsa_header = struct.pack(
        ">HBBIILHH", 0, 0, lsa_type, lsa_id, adv, 0x80000001, 0, 20 + len(payload)
    )
    body = struct.pack(">IIBxxx", 0, area, 0) + lsa_header + payload
    return struct.pack(">BBHL", 1, message_type, len(body), 0) + body


def test_receive_record_verifies_signature_and_requires_acceptance_callback():
    _, sign, verify = _signer()
    payload = encode_record(_record(), sign)
    reader, writer = socket.socketpair()
    adapter = FRROSPFv2OpaqueAdapter()
    adapter._async = reader
    accepted = []
    try:
        writer.sendall(_lsa_notification(12, payload))
        result = adapter.receive_record(verify, lambda record: accepted.append(record) or True)
        assert result["router_id"] == "192.0.2.1"
        assert accepted == [result]
    finally:
        adapter.close()
        writer.close()


def test_receive_record_rejects_stale_or_unauthorized_record_callback():
    _, sign, verify = _signer()
    payload = encode_record(_record(), sign)
    reader, writer = socket.socketpair()
    adapter = FRROSPFv2OpaqueAdapter()
    adapter._async = reader
    try:
        writer.sendall(_lsa_notification(12, payload))
        with pytest.raises(OSPFAPIError, match="stale or unauthorized"):
            adapter.receive_record(verify, lambda record: False)
    finally:
        adapter.close()
        writer.close()


def test_unrelated_lsa_delete_is_ignored_but_nls_delete_is_not_trusted():
    _, sign, verify = _signer()
    payload = encode_record(_record(), sign)
    reader, writer = socket.socketpair()
    adapter = FRROSPFv2OpaqueAdapter()
    adapter._async = reader
    try:
        writer.sendall(_lsa_notification(13, lsa_type=1))
        writer.sendall(_lsa_notification(12, payload))
        result = adapter.receive_record(verify, lambda record: True)
        assert result["record_seq"] == 1
    finally:
        adapter.close()
        writer.close()

    reader, writer = socket.socketpair()
    adapter = FRROSPFv2OpaqueAdapter()
    adapter._async = reader
    try:
        writer.sendall(_lsa_notification(13))
        with pytest.raises(OSPFAPIError, match="unsigned NLS LSA deletion"):
            adapter.receive_record(verify, lambda record: True)
    finally:
        adapter.close()
        writer.close()
