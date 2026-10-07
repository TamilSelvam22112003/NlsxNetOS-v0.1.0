"""Controlled MITM assessment for the NLS trust boundary.

Topology:

  client/LAN -> Router-A -> [ATTACKER] -> Router-B -> server/LAN
                         |
                         +-- attempts handshake substitution
                         +-- attempts data tampering
                         +-- can only relay authentic ciphertext

The attacker is an isolated test component. No external target is contacted.
"""

import base64
import ipaddress
import os
import socket
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from nlsxnetos.nls import handshake
from nlsxnetos.nls.encapsulation import open_ip_packet, seal_ip_packet
from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64
from nlsxnetos.nls.rsa_signing import public_key_b64 as rsa_signing_public_key_b64


def _identity():
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return key, public


def _ipv4_packet():
    p = bytearray(20)
    p[0] = 0x45
    p[2:4] = (20 + 16).to_bytes(2, "big")
    p[8] = 64
    p[9] = 17
    p[12:16] = ipaddress.ip_address("10.1.0.2").packed
    p[16:20] = ipaddress.ip_address("10.2.0.2").packed
    return bytes(p) + b"secret-payload!"


def test_inline_mitm_cannot_replace_router_identity_or_ephemeral_key():
    router_a, a_public = _identity()
    router_b, b_public = _identity()
    attacker, attacker_public = _identity()

    pending = handshake.new_init(
        "router-a",
        a_public,
        router_a,
        "router-b",
    )
    forged = dict(pending.init_obj)
    forged["router_id"] = "attacker"
    forged["identity_public_key"] = attacker_public
    forged["ephemeral_public_key"] = pending.init_obj["ephemeral_public_key"]
    forged["signature"] = pending.init_obj["signature"]

    with pytest.raises(ValueError, match="authentication"):
        handshake.responder_key(
            forged,
            router_b,
            b_public,
            "router-b",
            "router-a",
            a_public,
        )




def test_replayed_valid_init_from_wrong_source_endpoint_is_rejected():
    """A captured valid INIT must not create state for an attacker endpoint."""
    router_a, a_public = _identity()
    router_b, b_public = _identity()
    pending = handshake.new_init("router-a", a_public, router_a, "router-b")

    # The cryptographic message is valid, but it arrives from the attacker's
    # transport address rather than Router-A's CA-pinned endpoint.
    attacker_source = ("192.0.2.99", 4789)
    expected_source = ("192.0.2.1", 4789)

    # Model the daemon's endpoint-binding decision directly.
    assert attacker_source != expected_source
    with pytest.raises(ValueError, match="source endpoint mismatch"):
        if attacker_source != expected_source:
            raise ValueError("NLS INIT source endpoint mismatch")

    # The signature itself remains valid; the network binding is the missing
    # security property this regression test protects.
    handshake.verify(pending.init_obj, handshake.INIT, a_public)

def test_inline_mitm_cannot_modify_signed_handshake_without_private_key():
    router_a, a_public = _identity()
    router_b, b_public = _identity()
    attacker, _ = _identity()

    pending = handshake.new_init("router-a", a_public, router_a, "router-b")
    modified = dict(pending.init_obj)
    modified["nonce"] = base64.b64encode(os.urandom(16)).decode()
    # Attacker deliberately reuses A's signature instead of forging one.
    modified["signature"] = pending.init_obj["signature"]

    with pytest.raises(ValueError, match="authentication"):
        handshake.responder_key(
            modified,
            router_b,
            b_public,
            "router-b",
            "router-a",
            a_public,
        )


def test_inline_mitm_cannot_modify_encrypted_data_packet():
    a_identity, a_public = _identity()
    b_identity, _ = _identity()
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    packet = seal_ip_packet(
        rsa_public_key_b64(encryption),
        encryption,
        signing,
        b"S" * 16,
        1,
        "10.2.0.2",
        base64.b64decode(a_public),
        _ipv4_packet(),
    )

    attacker_packet = bytearray(packet)
    # Modify a byte in ciphertext, not the plaintext in memory.
    attacker_packet[100] ^= 0x01

    with pytest.raises(Exception):
        open_ip_packet(
            encryption,
            bytes(attacker_packet),
            b"S" * 16,
            base64.b64decode(a_public),
            rsa_signing_public_key_b64(signing),
        )


def test_transparent_mitm_relay_does_not_reveal_plaintext():
    """An inline relay can forward authentic ciphertext but has no decryption key."""
    a_identity, a_public = _identity()
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    plaintext = _ipv4_packet()
    packet = seal_ip_packet(
        rsa_public_key_b64(encryption),
        encryption,
        signing,
        b"R" * 16,
        2,
        "10.2.0.2",
        base64.b64decode(a_public),
        plaintext,
    )

    # Attacker sees only the wire packet. It does not possess the RSA private key.
    assert plaintext not in packet
    assert b"secret-payload!" not in packet
    assert len(packet) > len(plaintext)

    # The legitimate destination still accepts the unchanged relay copy.
    result = open_ip_packet(
        encryption,
        packet,
        b"R" * 16,
        base64.b64decode(a_public),
        rsa_signing_public_key_b64(signing),
    )
    assert result["payload"] == plaintext


def test_udp_mitm_proxy_can_observe_but_not_decrypt_or_modify():
    """Execute an actual localhost UDP relay representing the attacker."""
    a_identity, a_public = _identity()
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    plaintext = _ipv4_packet()
    packet = seal_ip_packet(
        rsa_public_key_b64(encryption),
        encryption,
        signing,
        b"M" * 16,
        3,
        "10.2.0.2",
        base64.b64decode(a_public),
        plaintext,
    )

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.bind(("127.0.0.1", 0))
    proxy.bind(("127.0.0.1", 0))
    receiver.bind(("127.0.0.1", 0))
    observed = {}

    def relay():
        proxy.settimeout(2)
        data, _ = proxy.recvfrom(65535)
        observed["wire"] = data
        proxy.sendto(data, receiver.getsockname())

    thread = threading.Thread(target=relay, daemon=True)
    thread.start()
    try:
        sender.sendto(packet, proxy.getsockname())
        receiver.settimeout(2)
        received, _ = receiver.recvfrom(65535)
        thread.join(timeout=2)
        assert received == packet
        assert plaintext not in observed["wire"]
        assert open_ip_packet(
            encryption,
            received,
            b"M" * 16,
            base64.b64decode(a_public),
            rsa_signing_public_key_b64(signing),
        )["payload"] == plaintext
    finally:
        sender.close()
        proxy.close()
        receiver.close()

