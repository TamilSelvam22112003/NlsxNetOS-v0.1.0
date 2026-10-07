import os
from cryptography.hazmat.primitives.asymmetric import rsa

from nlsxnetos.nls.encapsulation import open_ip_packet, seal_ip_packet
from nlsxnetos.nls.replay import ReplayWindow
from nlsxnetos.nls.rsa import public_key_b64
from nlsxnetos.nls.rsa_signing import public_key_b64 as signing_public_key_b64


def _packet():
    packet = bytearray(20)
    packet[0] = 0x45
    packet[2:4] = (20).to_bytes(2, "big")
    packet[8] = 64
    packet[9] = 17
    packet[12:16] = bytes([10, 1, 0, 2])
    packet[16:20] = bytes([10, 2, 0, 2])
    return bytes(packet) + b"payload"


def test_nls_data_round_trip_and_replay_rejection():
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    sid = os.urandom(16)
    identity = os.urandom(32)
    packet = seal_ip_packet(
        public_key_b64(encryption), encryption, signing,
        sid, 1, "10.2.0.2", identity, _packet(),
    )
    opened = open_ip_packet(
        encryption, packet, sid, identity, signing_public_key_b64(signing),
    )
    assert opened["payload"] == _packet()

    replay = ReplayWindow(64)
    assert replay.can_accept(1)
    assert replay.mark(1)
    assert not replay.can_accept(1)
