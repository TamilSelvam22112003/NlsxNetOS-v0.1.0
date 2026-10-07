import ipaddress

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from nlsxnetos.nls.encapsulation import open_ip_packet, peek_ip_packet, seal_ip_packet
from nlsxnetos.nls.replay import ReplayWindow
from nlsxnetos.nls.rsa import public_key_b64
from nlsxnetos.nls.rsa_signing import public_key_b64 as signing_public_key_b64


def ipv4_packet(destination="192.0.2.20", payload=b"attack-test"):
    source = ipaddress.IPv4Address("192.0.2.10").packed
    target = ipaddress.IPv4Address(destination).packed
    total_length = 20 + len(payload)
    return bytes([
        0x45, 0x00, (total_length >> 8) & 0xFF, total_length & 0xFF,
        0, 1, 0x40, 0, 64, 17, 0, 0,
    ]) + source + target + payload


def test_authenticated_packet_round_trip_and_forwarding_metadata():
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    session_id = b"S" * 16
    identity = b"I" * 32
    payload = ipv4_packet()

    packet = seal_ip_packet(
        public_key_b64(encryption.public_key()),
        public_key_b64(encryption),
        signing,
        session_id,
        7,
        "192.0.2.20",
        identity,
        payload,
    )

    metadata = peek_ip_packet(packet)
    assert metadata["destination_ip"] == "192.0.2.20"
    result = open_ip_packet(
        encryption,
        packet,
        session_id,
        identity,
        signing_public_key_b64(signing.public_key()),
    )
    assert result["payload"] == payload
    assert result["sequence"] == 7


@pytest.mark.parametrize("offset", [0, 20, -1])
def test_tampering_is_rejected(offset):
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    packet = seal_ip_packet(
        encryption.public_key(),
        encryption,
        signing,
        b"T" * 16,
        1,
        "192.0.2.20",
        b"I" * 32,
        ipv4_packet(),
    )
    tampered = bytearray(packet)
    tampered[offset] ^= 1
    with pytest.raises(ValueError):
        open_ip_packet(
            encryption,
            bytes(tampered),
            b"T" * 16,
            b"I" * 32,
            signing.public_key(),
        )


def test_wrong_signing_key_cannot_forge_data_packet():
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    trusted_signer = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    attacker_signer = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    packet = seal_ip_packet(
        encryption.public_key(),
        encryption,
        trusted_signer,
        b"K" * 16,
        1,
        "192.0.2.20",
        b"I" * 32,
        ipv4_packet(),
    )
    with pytest.raises(ValueError):
        open_ip_packet(
            encryption,
            packet,
            b"K" * 16,
            b"I" * 32,
            attacker_signer.public_key(),
        )


def test_replay_window_rejects_duplicate_and_old_packets():
    window = ReplayWindow(64)
    assert window.accept(100)
    assert not window.accept(100)
    assert window.accept(101)
    assert not window.accept(36)
    assert window.accept(165)
    assert not window.accept(100)


def test_oversized_rsa_packet_is_rejected():
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with pytest.raises(ValueError):
        seal_ip_packet(
            encryption.public_key(),
            encryption,
            signing,
            b"Z" * 16,
            1,
            "192.0.2.20",
            b"I" * 32,
            ipv4_packet() + (b"X" * 60000),
        )
