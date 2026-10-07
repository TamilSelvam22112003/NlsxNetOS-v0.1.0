import ipaddress
from unittest.mock import patch

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

    private = load_or_create("/tmp/nlsxnetos-forwarding-test.pem")
    payload = _ipv4_packet()
    packet = seal_ip_packet(
        public_key_b64(private),
        private,
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
        public_key_b64(private),
    )
    assert opened["payload"] == payload
    assert opened["destination_ip"] == "10.20.0.10"


def test_rsa_only_packet_contains_no_plaintext():
    from nlsxnetos.nls.rsa import load_or_create, public_key_b64

    private = load_or_create("/tmp/nlsxnetos-forwarding-test-plaintext.pem")
    payload = _ipv4_packet() + b"secret-message"
    packet = seal_ip_packet(
        public_key_b64(private),
        bytes(16),
        8,
        "10.20.0.10",
        bytes(range(32)),
        payload,
    )

    assert payload not in packet
    assert b"secret-message" not in packet


def test_kernel_route_parser_extracts_next_hop_and_interface():
    result = type("Result", (), {
        "returncode": 0,
        "stdout": "10.20.0.1 via 10.10.0.1 dev eth1 src 10.10.0.2\\n",
    })()
    with patch("nlsxnetos.nls.routing._run", return_value=result):
        route = _route_get("10.20.0.1")
    assert route == {"via": "10.10.0.1", "dev": "eth1"}
