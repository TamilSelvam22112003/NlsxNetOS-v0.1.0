import base64
import hashlib
import os
import random
import socket
import struct
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from nlsxnetos.nls import handshake
from nlsxnetos.nls.config import endpoint
from nlsxnetos.nls.encapsulation import HEADER, open_ip_packet, seal_ip_packet
from nlsxnetos.nls.replay import ReplayWindow
from nlsxnetos.nls.daemon import NLSDaemon
from nlsxnetos.router_ca.models import RouterCAEntry
from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64\nfrom nlsxnetos.nls.rsa_signing import public_key_b64 as rsa_signing_public_key_b64
from nlsxnetos.nls.rsa_signing import public_key_b64 as rsa_signing_public_key_b64


def _ipv4_packet(src="10.1.0.2", dst="10.2.0.2", payload=b"x"):
    p = bytearray(20)
    p[0] = 0x45
    p[2:4] = (20 + len(payload)).to_bytes(2, "big")
    p[8] = 64
    p[9] = 17
    import ipaddress
    p[12:16] = ipaddress.ip_address(src).packed
    p[16:20] = ipaddress.ip_address(dst).packed
    return bytes(p) + payload


def test_nls_udp_parser_fuzz_does_not_crash():
    rng = random.Random(0x4E4C53)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        target = server.getsockname()
        for _ in range(10000):
            packet = os.urandom(rng.randrange(0, 8193))
            client.sendto(packet, target)
            data, _addr = server.recvfrom(65535)
            try:
                handshake.decode_message(data)
            except (ValueError, UnicodeDecodeError, struct.error, TypeError, KeyError):
                pass
    finally:
        client.close()
        server.close()


def test_malformed_handshake_fuzz():
    rng = random.Random(1234)
    valid = handshake.encode_message(
        handshake.INIT,
        {
            "router_id": "r",
            "peer_id": "p",
            "identity_public_key": "A" * 44,
            "ephemeral_public_key": "B" * 44,
            "session_id": "00" * 16,
            "timestamp": int(time.time()),
            "nonce": "C" * 24,
            "protocol_version": 1,
        },
    )
    corpus = [b"", b"NLSH", b"NLSH\x01\x01\x00\x01{", valid[:-1]]
    for _ in range(10000):
        packet = bytearray(rng.choice(corpus) if rng.random() < 0.2 else os.urandom(rng.randrange(0, 512)))
        if len(packet) >= 8 and rng.random() < 0.7:
            packet[rng.randrange(len(packet))] ^= 1 << rng.randrange(8)
        try:
            handshake.decode_message(bytes(packet))
        except (ValueError, UnicodeDecodeError, struct.error, TypeError, KeyError):
            pass


def test_tun_packet_fuzz_is_bounded():
    rng = random.Random(0x54554E)
    for _ in range(20000):
        packet = os.urandom(rng.randrange(0, 4096))
        try:
            NLSDaemon._packet_destination(packet)
        except ValueError:
            pass


def test_replay_and_injection_are_rejected():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = rsa_public_key_b64(private_key)
    signing_private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing_public_key = rsa_signing_public_key_b64(signing_private_key)
    sid = os.urandom(16)
    identity = os.urandom(32)
    packet = _ipv4_packet()
    wrapped = seal_ip_packet(public_key, signing_private_key, sid, 7, "10.2.0.2", identity, packet)
    decoded = open_ip_packet(private_key, wrapped, sid, identity, signing_public_key)
    assert decoded["payload"] == packet

    replay = ReplayWindow(64)
    assert replay.can_accept(7)
    assert replay.mark(7)
    assert not replay.can_accept(7)
    assert not replay.mark(7)

    forged = bytearray(wrapped)
    forged[-1] ^= 0x80
    with pytest.raises(Exception):
        open_ip_packet(private_key, bytes(forged), sid, identity, signing_public_key)


def test_router_ca_impersonation_is_rejected():
    trusted = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    trusted_pub = base64.b64encode(trusted.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    attacker_pub = base64.b64encode(attacker.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

    forged = handshake.sign(
        {
            "router_id": "attacker",
            "peer_id": "router-b",
            "identity_public_key": attacker_pub,
            "ephemeral_public_key": base64.b64encode(os.urandom(32)).decode(),
            "session_id": os.urandom(16).hex(),
            "timestamp": int(time.time()),
            "nonce": base64.b64encode(os.urandom(16)).decode(),
            "protocol_version": 1,
        },
        handshake.INIT,
        attacker,
    )
    with pytest.raises(ValueError):
        handshake.verify(forged, handshake.INIT, trusted_pub)

    entry = RouterCAEntry(1, "10.2.0.0/24", "router-b", trusted_pub, "192.0.2.2:4789")
    entry.validate()
    assert entry.public_key != attacker_pub


@pytest.mark.parametrize(
    "value,valid",
    [
        ("192.0.2.2:4789", True),
        ("[2001:db8::2]:4789", True),
        ("192.0.2.2:0", False),
        ("192.0.2.2:65536", False),
        ("2001:db8::2:4789", False),
        ("[2001:db8::2]", False),
        ("hostname.example:4789", False),
        ("192.0.2.2:not-a-port", False),
    ],
)
def test_endpoint_validation(value, valid):
    if valid:
        host, port = endpoint(value)
        assert port == 4789
    else:
        with pytest.raises(ValueError):
            endpoint(value)


def test_router_ca_prefix_is_network_validated():
    with pytest.raises(ValueError):
        RouterCAEntry(1, "not-an-ip-prefix", "x").validate()


def test_default_configuration_is_not_nls_network_exposed():
    # This regression test is intentionally static: NLS must remain disabled
    # until Router-CA is configured and an explicit WAN bind is selected.
    from pathlib import Path
    text = Path("config/nls.yaml").read_text(encoding="utf-8")
    assert "enabled: false" in text
    assert 'bind_interface: ""' in text
