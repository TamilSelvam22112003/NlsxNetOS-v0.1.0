import ipaddress

import pytest

from nls.encapsulation import (
    HEADER,
    HEADER_SIZE,
    MAGIC,
    MAX_PACKETS_PER_KEY,
    open_ip_packet,
    seal_ip_packet,
)
from nls.replay import ReplayWindow


def ipv4_packet(source="10.0.0.10", destination="203.0.113.10", payload=b"tcp-payload"):
    packet = bytearray(20)
    packet[0] = 0x45
    packet[2:4] = (20 + len(payload)).to_bytes(2, "big")
    packet[8] = 64
    packet[9] = 6
    packet[12:16] = ipaddress.IPv4Address(source).packed
    packet[16:20] = ipaddress.IPv4Address(destination).packed
    return bytes(packet) + payload


def ipv6_packet(source="2001:db8:1::10", destination="2001:db8:2::10", payload=b"udp-data"):
    packet = bytearray(40)
    packet[0] = 0x60
    packet[4:6] = len(payload).to_bytes(2, "big")
    packet[6] = 17
    packet[7] = 64
    packet[8:24] = ipaddress.IPv6Address(source).packed
    packet[24:40] = ipaddress.IPv6Address(destination).packed
    return bytes(packet) + payload


@pytest.fixture
def session_material():
    return bytes(range(32)), bytes.fromhex("00112233445566778899aabbccddeeff"), b"IVP2"


def test_nle2_round_trip_uses_32_byte_header_as_aad(session_material):
    key, sid, iv_prefix = session_material
    original = ipv4_packet()
    outer = seal_ip_packet(key, sid, 7, iv_prefix, original)
    assert len(outer) == HEADER_SIZE + len(original) + 16
    assert HEADER_SIZE == 32
    assert outer[:4] == b"NLE2"
    assert HEADER.unpack(outer[:HEADER_SIZE]) == (b"NLE2", 2, bytes(3), sid, 7)
    assert ipaddress.IPv4Address("10.0.0.10").packed not in outer[:HEADER_SIZE]
    assert b"tcp-payload" not in outer
    assert open_ip_packet(key, outer, sid, iv_prefix) == original


def test_ipv6_inner_packet_round_trip(session_material):
    key, sid, iv_prefix = session_material
    original = ipv6_packet()
    packet = seal_ip_packet(key, sid, 1, iv_prefix, original)
    assert open_ip_packet(key, packet, sid, iv_prefix) == original
    assert ipaddress.IPv6Address("2001:db8:2::10").packed not in packet[:HEADER_SIZE]


@pytest.mark.parametrize("offset", [4, 8, 31, -1])
def test_tampered_header_or_ciphertext_rejected(session_material, offset):
    key, sid, iv_prefix = session_material
    packet = bytearray(seal_ip_packet(key, sid, 8, iv_prefix, ipv4_packet()))
    packet[offset] ^= 0x01
    with pytest.raises(ValueError):
        open_ip_packet(key, bytes(packet), sid, iv_prefix)


def test_wrong_session_and_wrong_direction_key_rejected(session_material):
    key, sid, iv_prefix = session_material
    packet = seal_ip_packet(key, sid, 2, iv_prefix, ipv4_packet())
    with pytest.raises(ValueError, match="session"):
        open_ip_packet(key, b"".join((packet[:8], b"X" * 16, packet[24:])), sid, iv_prefix)
    with pytest.raises(ValueError, match="authentication"):
        open_ip_packet(bytes(reversed(key)), packet, sid, iv_prefix)


def test_replay_window_not_poisoned_by_failed_authentication(session_material):
    key, sid, iv_prefix = session_material
    replay = ReplayWindow(128)
    packet = bytearray(seal_ip_packet(key, sid, 900, iv_prefix, ipv4_packet()))
    packet[-1] ^= 0x80
    sequence = HEADER.unpack(packet[:HEADER_SIZE])[4]
    assert replay.can_accept(sequence)
    with pytest.raises(ValueError, match="authentication"):
        open_ip_packet(key, bytes(packet), sid, iv_prefix)
    assert replay.highest == -1
    assert replay.can_accept(sequence)
    valid = seal_ip_packet(key, sid, sequence, iv_prefix, ipv4_packet())
    assert open_ip_packet(key, valid, sid, iv_prefix) == ipv4_packet()
    assert replay.mark(sequence)
    assert not replay.can_accept(sequence)


def test_out_of_window_and_sequence_bounds(session_material):
    key, sid, iv_prefix = session_material
    replay = ReplayWindow(128)
    assert replay.mark(1000)
    assert not replay.can_accept(872)
    assert not replay.can_accept(-1)
    assert not replay.can_accept(1 << 64)
    with pytest.raises(ValueError, match="rekey"):
        seal_ip_packet(key, sid, MAX_PACKETS_PER_KEY, iv_prefix, ipv4_packet())


def test_strict_header_and_length_bounds(session_material):
    key, sid, iv_prefix = session_material
    packet = seal_ip_packet(key, sid, 3, iv_prefix, ipv4_packet())
    with pytest.raises(ValueError, match="too short"):
        open_ip_packet(key, packet[:HEADER_SIZE + 15], sid, iv_prefix)
    bad_flags = bytearray(packet)
    bad_flags[5] = 1
    with pytest.raises(ValueError, match="header"):
        open_ip_packet(key, bytes(bad_flags), sid, iv_prefix)
    with pytest.raises(ValueError, match="length"):
        seal_ip_packet(key, sid, 4, iv_prefix, b"")


def test_active_data_path_does_not_wrap_per_packet_rsa_keys():
    import inspect
    from nls import encapsulation
    from nls.daemon import NLSDaemon

    encapsulation_source = inspect.getsource(encapsulation)
    sender_source = inspect.getsource(NLSDaemon._send_payload)
    assert "wrap_key" not in encapsulation_source
    assert "unwrap_key" not in encapsulation_source
    assert "rsa" not in sender_source.lower()
