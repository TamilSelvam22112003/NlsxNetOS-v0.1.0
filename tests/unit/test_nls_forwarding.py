import ipaddress
from unittest.mock import patch

import pytest

from nlsxnetos.nls.encapsulation import HEADER, open_ip_packet, peek_ip_packet, seal_ip_packet
from nlsxnetos.nls.routing import _route_get


def _ipv4_packet(source="10.10.0.10", destination="10.20.0.10"):
    packet = bytearray(20)
    packet[0] = 0x45
    packet[2:4] = (20).to_bytes(2, "big")
    packet[8] = 64
    packet[9] = 17
    packet[12:16] = ipaddress.IPv4Address(source).packed
    packet[16:20] = ipaddress.IPv4Address(destination).packed
    return bytes(packet) + b"nls"


def test_rsa_only_round_trip():
    from nlsxnetos.nls.rsa import load_or_create, public_key_b64
    from nlsxnetos.nls.rsa_signing import load_or_create as load_signing, public_key_b64 as signing_public_key_b64

    private = load_or_create("/tmp/nlsxnetos-forwarding-test.pem")
    signing = load_signing("/tmp/nlsxnetos-forwarding-test-signing.pem")
    payload = _ipv4_packet()
    packet = seal_ip_packet(
        public_key_b64(private),
        private,
        signing,
        bytes(16),
        7,
        "10.20.0.10",
        bytes(range(32)),
        payload,
    )
    metadata = peek_ip_packet(packet)

    assert metadata["destination_ip"] == "10.20.0.10"
    assert metadata["sequence"] == 7
    assert metadata["session_id"] == bytes(16)
    assert HEADER.size < len(packet)

    opened = open_ip_packet(
        private,
        packet,
        bytes(16),
        bytes(range(32)),
        signing_public_key_b64(signing),
    )
    assert opened["payload"] == payload
    assert opened["destination_ip"] == "10.20.0.10"


def test_rsa_only_packet_contains_no_plaintext():
    from nlsxnetos.nls.rsa import load_or_create, public_key_b64

    private = load_or_create("/tmp/nlsxnetos-forwarding-test-plaintext.pem")
    signing = load_signing("/tmp/nlsxnetos-forwarding-test-plaintext-signing.pem")
    payload = _ipv4_packet() + b"secret-message"
    packet = seal_ip_packet(
        public_key_b64(private),
        private,
        bytes(16),
        8,
        "10.20.0.10",
        bytes(range(32)),
        payload,
    )

    assert payload not in packet
    assert b"secret-message" not in packet


def test_rsa_only_multiblock_and_header_tamper_rejected():
    from nlsxnetos.nls.rsa import load_or_create, public_key_b64

    private = load_or_create("/tmp/nlsxnetos-forwarding-test-multiblock.pem")
    signing = load_signing("/tmp/nlsxnetos-forwarding-test-multiblock-signing.pem")
    payload = _ipv4_packet() + b"x" * 700
    packet = seal_ip_packet(
        public_key_b64(private),
        private,
        bytes(16),
        9,
        "10.20.0.10",
        bytes(range(32)),
        payload,
    )

    opened = open_ip_packet(
        private,
        packet,
        bytes(16),
        bytes(range(32)),
        signing_public_key_b64(signing),
    )
    assert opened["payload"] == payload

    tampered = bytearray(packet)
    tampered[40] ^= 1
    with pytest.raises(ValueError):
        open_ip_packet(
            private,
            bytes(tampered),
            bytes(16),
            bytes(range(32)),
            public_key_b64(private),
        )


def test_kernel_route_parser_extracts_next_hop_and_interface():
    result = type("Result", (), {
        "returncode": 0,
        "stdout": "10.20.0.1 via 10.10.0.1 dev eth1 src 10.10.0.2\\n",
    })()
    with patch("nlsxnetos.nls.routing._run", return_value=result):
        route = _route_get("10.20.0.1")
    assert route == {"via": "10.10.0.1", "dev": "eth1"}


def test_destination_rejects_unknown_nls_initiator():
    from types import SimpleNamespace
    from nlsxnetos.nls.daemon import NLSDaemon

    cfg = SimpleNamespace(
        identity_key="/tmp/nlsxnetos-test-identity",
        encryption_private_key="/tmp/nlsxnetos-test-rsa.pem",
        signing_private_key="/tmp/nlsxnetos-test-signing.pem",
        router_id="dest",
        router_ca_server_url="",
        router_ca_timeout_seconds=5,
        router_ca_ca_file="",
        router_ca_bearer_token="",
        peer_block_seconds=60,
        max_clock_skew_seconds=120,
        session_timeout_seconds=300,
        peers=[],
    )
    daemon = NLSDaemon(cfg)
    assert daemon._peer_from_router_ca_identity("not-registered") is None
