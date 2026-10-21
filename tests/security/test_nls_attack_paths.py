"""Attack-path regression tests for the NLS authenticated data plane.

These are unit-level security tests; they do not replace the multi-router
integration lab or packet-capture validation.
"""

import pytest

from nls.encapsulation import open_ip_packet, seal_ip_packet
from nls.replay import ReplayWindow
from nls.source_token import open_source_token_payload, seal_source_token_payload
from nls.v2_runtime import (
    MAX_SOURCE_BUCKETS,
    SOURCE_BUCKET_TTL,
    HandshakeV2,
)


def _ipv6_packet(source="2001:db8:1::1", destination="2001:db8:2::2"):
    """Build a minimal valid 40-byte IPv6 packet with no payload."""
    import ipaddress

    packet = bytearray(40)
    packet[0] = 0x60
    packet[6] = 59  # No Next Header
    packet[7] = 64
    packet[8:24] = ipaddress.IPv6Address(source).packed
    packet[24:40] = ipaddress.IPv6Address(destination).packed
    return bytes(packet)


def test_nle2_rejects_ciphertext_tampering():
    key = bytes(range(32))
    session_id = bytes(range(16))
    iv_prefix = b"\x01\x02\x03\x04"
    packet = bytearray(seal_ip_packet(key, session_id, 7, iv_prefix, _ipv6_packet()))
    packet[-1] ^= 0x80

    with pytest.raises(ValueError, match="authentication failed"):
        open_ip_packet(key, bytes(packet), session_id, iv_prefix)


def test_nle2_rejects_header_tampering_even_with_original_ciphertext():
    key = b"K" * 32
    session_id = b"S" * 16
    iv_prefix = b"IVP!"
    packet = bytearray(seal_ip_packet(key, session_id, 3, iv_prefix, _ipv6_packet()))
    packet[31] ^= 1  # Sequence is part of the authenticated header/AAD.

    with pytest.raises(ValueError):
        open_ip_packet(key, bytes(packet), session_id, iv_prefix)


def test_nle2_rejects_wrong_session_binding():
    key = b"K" * 32
    session_id = b"A" * 16
    wrong_session_id = b"B" * 16
    packet = seal_ip_packet(key, session_id, 1, b"IVP!", _ipv6_packet())

    with pytest.raises(ValueError, match="wrong session"):
        open_ip_packet(key, packet, wrong_session_id, b"IVP!")


def test_source_token_authentication_binds_outer_addresses():
    key = b"K" * 32
    iv_prefix = b"IVP!"
    packet = seal_source_token_payload(
        key, iv_prefix, 9, "2001:db8:10::1", "2001:db8:20::1", _ipv6_packet()
    )

    counter, message_type, body = open_source_token_payload(
        key, iv_prefix, packet, "2001:db8:10::1", "2001:db8:20::1"
    )
    assert (counter, message_type, body) == (9, 0, _ipv6_packet())

    with pytest.raises(ValueError, match="authentication failed"):
        open_source_token_payload(
            key, iv_prefix, packet, "2001:db8:10::9", "2001:db8:20::1"
        )


def test_forged_high_counter_does_not_poison_live_session(monkeypatch):
    """A forged max counter with a bad tag must not advance the session replay window."""
    from types import SimpleNamespace

    from nls.daemon import NLSDaemon

    key = b"R" * 32
    iv_prefix = b"IVP!"
    source_token = "2001:4860:4860::1"
    local_original_ip = "2001:4860:4860::2"
    inner_packet = _ipv6_packet(destination="2001:db8:2::2")
    replay = ReplayWindow()
    session_id = b"session-attack!"
    session = SimpleNamespace(
        peer_id="peer-A",
        state="ESTABLISHED",
        recv_token=source_token,
        recv_key=key,
        recv_iv_prefix=iv_prefix,
        recv_replay=replay,
        local_record={"originalIP": local_original_ip},
        bytes_received=0,
        packets_received=0,
        last_seen=0.0,
    )

    class FakeV2:
        @staticmethod
        def is_retired_vip(_address):
            return False

        @staticmethod
        def _cached_record(_router_id):
            return {"prefixes": ["2001:db8:2::/64"]}

    daemon = object.__new__(NLSDaemon)
    daemon.v2 = FakeV2()
    daemon.sessions = {session_id: session}
    daemon.source_token_sessions = {source_token: session_id}
    daemon.cfg = SimpleNamespace(enforce_inner_source_prefix=False, router_id="router-B")
    daemon.tun = SimpleNamespace(write=lambda _packet: None)
    daemon.stats = {"drops": 0, "data_drops": 0, "rx": 0}
    daemon.reason_counters = {}

    forged = bytearray(seal_source_token_payload(
        key, iv_prefix, (1 << 32) - 1, source_token, local_original_ip, inner_packet
    ))
    forged[-1] ^= 1
    daemon._handle_data(bytes(forged), (source_token, 4789), session_id)
    assert replay.highest == -1

    valid = seal_source_token_payload(
        key, iv_prefix, 1, source_token, local_original_ip, inner_packet
    )
    daemon._handle_data(valid, (source_token, 4789), session_id)
    assert replay.highest == 1
    assert daemon.stats["rx"] == 1
    assert session.packets_received == 1


def test_retired_vip_is_rejected_and_expired_retirement_is_forgotten(monkeypatch):
    runtime = object.__new__(HandshakeV2)
    runtime.retired_vips = {
        "2001:db8::10": 120.0,
        "2001:db8::11": 99.0,
    }
    monkeypatch.setattr("nls.v2_runtime.time.monotonic", lambda: 100.0)

    assert runtime.is_retired_vip("2001:0db8:0:0:0:0:0:10")
    assert not runtime.is_retired_vip("2001:db8::11")
    assert "2001:db8::11" not in runtime.retired_vips


def test_handshake_source_bucket_table_stays_bounded(monkeypatch):
    runtime = object.__new__(HandshakeV2)
    runtime.buckets = {}
    runtime._bucket_sweep_counter = 0
    monkeypatch.setattr("nls.v2_runtime.time.monotonic", lambda: 100.0)

    for index in range(MAX_SOURCE_BUCKETS + 100):
        # Unique syntactically valid IPv6 sources simulate address rotation.
        runtime._allow_source((f"2001:db8::{index + 1:x}", 4790))

    assert len(runtime.buckets) <= MAX_SOURCE_BUCKETS


def test_handshake_source_bucket_expiry_is_bounded(monkeypatch):
    runtime = object.__new__(HandshakeV2)
    runtime.buckets = {"2001:db8::1": (0.0, 100.0)}
    runtime._bucket_sweep_counter = 63
    monkeypatch.setattr("nls.v2_runtime.time.monotonic", lambda: 100.0 + SOURCE_BUCKET_TTL + 1)

    # The 64th call sweeps expired state and admits the new source.
    assert runtime._allow_source(("2001:db8::2", 4790))
    assert "2001:db8::1" not in runtime.buckets


def test_malformed_source_address_is_rejected_without_exception():
    runtime = object.__new__(HandshakeV2)
    runtime.buckets = {}
    assert not runtime._allow_source(("not-an-ip-address", 4790))
    assert runtime.buckets == {}
