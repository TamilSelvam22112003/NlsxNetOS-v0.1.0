import ipaddress
import threading
import time
from types import SimpleNamespace

import pytest

from nls.daemon import NLSDaemon
from nls.replay import ReplayWindow
from nls.source_token import open_source_token_payload, seal_source_token_payload


def _ipv6_packet(source="2001:db8:1::10", destination="2001:db8:2::20"):
    packet = bytearray(40)
    packet[0] = 0x60
    packet[4:6] = (0).to_bytes(2, "big")
    packet[6] = 59
    packet[7] = 64
    packet[8:24] = ipaddress.IPv6Address(source).packed
    packet[24:40] = ipaddress.IPv6Address(destination).packed
    return bytes(packet)


class _FakeSocket:
    def __init__(self):
        self.sent = []

    def sendto(self, packet, endpoint):
        self.sent.append((packet, endpoint))


class _FakeTun:
    def __init__(self):
        self.written = []

    def write(self, packet):
        self.written.append(packet)


@pytest.mark.parametrize("mode,wire_mode", [
    ("source-only", 1),
    ("source-destination", 2),
])
def test_daemon_sender_uses_configured_metadata_mode(mode, wire_mode):
    key = bytes(range(32))
    source_token = "2001:4860:4860::1234"
    peer_wan = "2606:4700:4700::1234"
    packet = _ipv6_packet()
    sock = _FakeSocket()
    session = SimpleNamespace(
        peer_id="peer",
        endpoint=(peer_wan, 4789),
        state="ESTABLISHED",
        send_key=key,
        send_iv_prefix=b"iv01",
        send_token=source_token,
        tx_sequence=0,
        key_lock=threading.RLock(),
        created_mono=time.monotonic(),
        token_lease=SimpleNamespace(sock=sock),
        last_tx=0.0,
        bytes_sent=0,
        packets_sent=0,
    )
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(
        metadata_mode=mode,
        rekey_packet_limit=1 << 32,
        rekey_seconds=3600,
    )
    daemon.sessions = {b"session": session}
    daemon.peers = {"peer": SimpleNamespace(id="peer")}
    daemon.stats = {"tx": 0, "drops": 0, "data_drops": 0}
    daemon._packet_destination = lambda _payload: "2001:db8:2::20"
    daemon._session_for_destination = lambda _destination: session

    assert daemon._send_payload(packet) is True
    assert len(sock.sent) == 1
    wire, endpoint = sock.sent[0]
    assert endpoint == (peer_wan, 4789)
    assert wire[:4] == b"NLD2"
    assert wire[5] == wire_mode
    assert session.tx_sequence == 1
    assert daemon.stats["tx"] == 1
    assert open_source_token_payload(
        key, b"iv01", wire, source_token, peer_wan, metadata_mode=mode
    ) == (0, 0, packet)


@pytest.mark.parametrize("mode", ["source-only", "source-destination"])
def test_daemon_receiver_authenticates_before_forwarding_and_rejects_replay(mode):
    key = bytes(range(32))
    source_token = "2001:4860:4860::1234"
    local_original_ip = "2606:4700:4700::1234"
    packet = _ipv6_packet()
    wire = seal_source_token_payload(
        key, b"iv01", 0, source_token, local_original_ip, packet,
        metadata_mode=mode,
    )
    session = SimpleNamespace(
        peer_id="peer",
        state="ESTABLISHED",
        recv_token=source_token,
        recv_key=key,
        recv_iv_prefix=b"iv01",
        recv_replay=ReplayWindow(),
        local_record={"originalIP": local_original_ip},
        last_seen=0.0,
        bytes_received=0,
        packets_received=0,
    )
    tun = _FakeTun()
    daemon = NLSDaemon.__new__(NLSDaemon)
    daemon.cfg = SimpleNamespace(metadata_mode=mode, enforce_inner_source_prefix=False)
    daemon.sessions = {b"session": session}
    daemon.source_token_sessions = {source_token: b"session"}
    daemon.v2 = SimpleNamespace(is_retired_vip=lambda _address: False)
    daemon.tun = tun
    daemon.stats = {"rx": 0, "drops": 0, "data_drops": 0}
    daemon._validate_inner_destination_prefix = lambda _payload: None

    daemon._handle_data(wire, (source_token, 4789))
    assert tun.written == [packet]
    assert daemon.stats["rx"] == 1
    assert session.recv_replay.highest == 0

    daemon._handle_data(wire, (source_token, 4789))
    assert tun.written == [packet]
    assert daemon.stats["rx"] == 1
    assert daemon.stats["drops"] == 1
    assert session.recv_replay.highest == 0
