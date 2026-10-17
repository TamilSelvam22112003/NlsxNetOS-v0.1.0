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

from nls import handshake
from nls.config import endpoint
from nls.encapsulation import HEADER, open_ip_packet, seal_ip_packet
from nls.replay import ReplayWindow
from nls.daemon import NLSDaemon
from security.trust.router_ca.models import RouterCAEntry


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
                handshake.decode_v2_envelope(data)
            except (ValueError, UnicodeDecodeError, struct.error, TypeError, KeyError):
                pass
    finally:
        client.close()
        server.close()


def test_malformed_handshake_fuzz():
    rng = random.Random(1234)
    identity = Ed25519PrivateKey.generate()
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    session_id = os.urandom(16)
    obj = handshake.sign_v2(
        handshake.M1,
        {
            "session_id": session_id,
            "router_id": "router-fuzz",
            "ed25519_public_key": identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            "rsa_encryption_public_key": recipient.public_key().public_bytes(
                Encoding.PEM, __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo
            ),
            "nonce_s": os.urandom(32),
            "timestamp": int(time.time()),
            "vip": "fd00::1",
            "padding": os.urandom(7600),
        },
        identity,
    )
    valid = handshake.encode_v2_message(handshake.M1, session_id, recipient.public_key(), obj)
    corpus = [b"", b"NLH2", valid, valid[:-1]]
    for _ in range(10000):
        packet = bytearray(rng.choice(corpus) if rng.random() < 0.2 else os.urandom(rng.randrange(0, 512)))
        if len(packet) >= 8 and rng.random() < 0.7:
            packet[rng.randrange(len(packet))] ^= 1 << rng.randrange(8)
        try:
            handshake.decode_v2_envelope(bytes(packet))
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
        try:
            NLSDaemon._inner_addresses(packet)
        except ValueError:
            pass


def test_replay_and_injection_are_rejected():
    from nls.encapsulation import HEADER_SIZE, open_ip_packet, seal_ip_packet

    key = os.urandom(32)
    sid = os.urandom(16)
    iv_prefix = os.urandom(4)
    packet = _ipv4_packet()
    wrapped = seal_ip_packet(key, sid, 7, iv_prefix, packet)
    assert open_ip_packet(key, wrapped, sid, iv_prefix) == packet

    replay = ReplayWindow(128)
    assert replay.can_accept(7)
    forged = bytearray(wrapped)
    forged[-1] ^= 0x80
    with pytest.raises(ValueError, match="authentication"):
        open_ip_packet(key, bytes(forged), sid, iv_prefix)
    # Failed AEAD verification must not advance or poison the window.
    assert replay.highest == -1
    assert replay.can_accept(7)
    assert replay.mark(7)
    assert not replay.can_accept(7)

    # Public header/session information is insufficient to forge an AEAD tag.
    public_only_forgery = bytearray(wrapped[:HEADER_SIZE] + os.urandom(len(wrapped) - HEADER_SIZE))
    with pytest.raises(ValueError):
        open_ip_packet(key, bytes(public_only_forgery), sid, iv_prefix)


def test_nle2_udp_parser_fuzz_is_bounded():
    from nls.encapsulation import open_ip_packet

    rng = random.Random(0x4E4C4532)
    key, sid, prefix = os.urandom(32), os.urandom(16), os.urandom(4)
    for _ in range(10000):
        packet = os.urandom(rng.randrange(0, 2049))
        try:
            open_ip_packet(key, packet, sid, prefix)
        except (ValueError, TypeError, struct.error):
            pass


def test_router_ca_impersonation_is_rejected():
    trusted = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    trusted_raw = trusted.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    trusted_pub = base64.b64encode(trusted_raw).decode()
    attacker_raw = attacker.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    attacker_pub = base64.b64encode(attacker_raw).decode()
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    session_id = os.urandom(16)
    forged = handshake.sign_v2(
        handshake.M1,
        {
            "session_id": session_id,
            "router_id": "attacker",
            "ed25519_public_key": attacker_raw,
            "rsa_encryption_public_key": encryption.public_key().public_bytes(
                Encoding.PEM, __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo
            ),
            "nonce_s": os.urandom(32),
            "timestamp": int(time.time()),
            "vip": "fd00::1",
            "padding": os.urandom(7600),
        },
        attacker,
    )
    with pytest.raises(ValueError, match="NLS_HS_SIGNATURE_INVALID"):
        handshake.verify_v2_signature(handshake.M1, forged, trusted_raw)

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
    text = Path("config/nls/nls.yaml").read_text(encoding="utf-8")
    assert "enabled: false" in text
    assert 'bind_interface: ""' in text


def test_nlh2_parser_fuzz_is_bounded_and_exception_safe():
    from cryptography.hazmat.primitives.asymmetric import rsa
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rng = random.Random(0x4E4C4832)
    for _ in range(2000):
        packet = os.urandom(rng.randrange(0, 1200))
        try:
            handshake.decode_v2_envelope(packet)
        except ValueError:
            pass
        # A syntactically valid outer header with hostile envelope bytes must
        # also fail as a normalized ValueError, never an uncaught parser error.
        sid = os.urandom(16)
        envelope = os.urandom(rng.randrange(414, 900))
        packet = handshake.V2_HEADER.pack(
            handshake.V2_MAGIC, handshake.V2_VERSION, handshake.M1, sid, len(envelope)
        ) + envelope
        with pytest.raises(ValueError):
            handshake.open_v2_message(packet, private)
