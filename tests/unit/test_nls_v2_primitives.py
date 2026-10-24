import os
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519

from nls import handshake
from nls.seal import SealError, open_seal, seal
from nls.key_schedule import derive_session_keys, transcript_hash


def test_seal_round_trip_and_aad_binding():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = private.public_key()
    plaintext = b"bounded handshake test"
    envelope = seal(public, plaintext, b"NLH2\x01\x01" + bytes(16))
    assert open_seal(private, envelope, b"NLH2\x01\x01" + bytes(16)) == plaintext
    with pytest.raises(SealError):
        open_seal(private, envelope, b"wrong aad")
    with pytest.raises(SealError):
        open_seal(private, envelope[:-1], b"NLH2\x01\x01" + bytes(16))


def test_seal_rejects_oversized_plaintext_and_malformed_envelope():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with pytest.raises(SealError):
        seal(private.public_key(), b"x" * (16 * 1024 + 1), b"aad")
    for packet in (b"", b"\x00", os.urandom(32), b"\x01\x80" + os.urandom(500)):
        with pytest.raises(SealError):
            open_seal(private, packet, b"aad")


def test_nlh2_deterministic_cbor_schema_and_signature():
    identity = ed25519.Ed25519PrivateKey.generate()
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    sid = os.urandom(16)
    obj = {
        "session_id": sid,
        "router_id": "router-s",
        "ed25519_public_key": identity.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "rsa_encryption_public_key": rsa_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        "nonce_s": os.urandom(32),
        "timestamp": 1900000000,
        "vip": "fd42:4e4c:53::1234",
        "padding": os.urandom(7000),
    }
    signed = handshake.sign_v2(handshake.M1, obj, identity)
    packet = handshake.encode_v2_message(handshake.M1, sid, rsa_private.public_key(), signed)
    kind, decoded_sid, opened, plaintext = handshake.open_v2_message(packet, rsa_private)
    assert kind == handshake.M1
    assert decoded_sid == sid
    assert opened == signed
    assert plaintext
    handshake.verify_v2_signature(handshake.M1, opened, obj["ed25519_public_key"])
    tampered = dict(opened)
    tampered["unexpected"] = True
    with pytest.raises(ValueError):
        handshake.encode_v2_message(handshake.M1, sid, rsa_private.public_key(), tampered)


def test_nlh2_rejects_bad_header_and_trailing_bytes():
    with pytest.raises(ValueError):
        handshake.decode_v2_envelope(b"NLH2" + bytes(20))
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    identity = ed25519.Ed25519PrivateKey.generate()
    sid = os.urandom(16)
    obj = {
        "session_id": sid, "router_id": "router-s",
        "ed25519_public_key": identity.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        "rsa_encryption_public_key": private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        "nonce_s": os.urandom(32), "timestamp": 1900000000,
        "vip": "fd42:4e4c:53::1234", "padding": os.urandom(7000),
    }
    packet = handshake.encode_v2_message(
        handshake.M1, sid, private.public_key(), handshake.sign_v2(handshake.M1, obj, identity))
    with pytest.raises(ValueError):
        handshake.decode_v2_envelope(packet + b"trailing")


def test_transcript_and_directional_key_schedule():
    a = x25519.X25519PrivateKey.generate()
    b = x25519.X25519PrivateKey.generate()
    ap = a.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    bp = b.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sid = os.urandom(16)
    h3 = transcript_hash(b"m1", b"m2", b"m3")
    a_keys = derive_session_keys(a, bp, h3, sid)
    b_keys = derive_session_keys(b, ap, h3, sid)
    assert a_keys == b_keys
    assert len(a_keys["k_confirm"]) == 32
    assert len(a_keys["s_to_d_key"]) == 32
    assert len(a_keys["d_to_s_key"]) == 32
    assert len(a_keys["s_to_d_iv_prefix"]) == 4
    assert len(a_keys["d_to_s_iv_prefix"]) == 4
    assert transcript_hash(b"ab", b"c") != transcript_hash(b"a", b"bc")


def test_x25519_all_zero_peer_is_rejected():
    a = x25519.X25519PrivateKey.generate()
    ap = a.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with pytest.raises(ValueError):
        derive_session_keys(a, bytes(32), bytes(32), bytes(16))


def test_handshake_uses_envelope_from_same_lookup_response(monkeypatch):
    from types import SimpleNamespace

    from nls import ca_client
    from nls.v2_runtime import HandshakeV2

    runtime = HandshakeV2.__new__(HandshakeV2)
    runtime.owner = SimpleNamespace(
        cfg=SimpleNamespace(router_id="router-a"),
        identity=object(),
    )
    settings = object()
    runtime._settings = lambda: settings
    runtime._validate_record = lambda record, fresh: None
    record = {"router_id": "router-b", "record_seq": 4}
    envelope = {"payload": {"router_id": "router-b", "record_seq": 4}, "signature": "signed"}
    calls = {}

    def lookup(_settings, _identity, router_id, *, include_envelope=False):
        calls["include_envelope"] = include_envelope
        calls["router_id"] = router_id
        assert include_envelope is True
        return record, envelope

    monkeypatch.setattr(ca_client, "lookup", lookup)
    monkeypatch.setattr(
        ca_client, "lookup_envelope",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("handshake must not reread the shared lookup cache")
        ),
    )
    monkeypatch.setattr(ca_client, "_verify_directory_envelope", lambda _envelope, _settings: record)

    returned_record, returned_envelope = runtime._record_envelope("router-b")
    assert returned_record is record
    assert returned_envelope is envelope
    assert calls == {"include_envelope": True, "router_id": "router-b"}


def test_simultaneous_rekey_arbitration_is_stable_for_initiator_and_responder():
    from types import SimpleNamespace

    from nls.v2_runtime import HandshakeV2

    runtime = HandshakeV2.__new__(HandshakeV2)
    runtime.owner = SimpleNamespace(cfg=SimpleNamespace(router_id="router-a"))
    runtime.pending = {
        b"local": {"role": "S", "rekey": True, "peer_id": "router-b"},
    }
    dropped = []
    runtime._drop = lambda reason, addr, stage: dropped.append((reason, stage))
    runtime._abort = lambda sid, reason, addr=None: runtime.pending.pop(sid, None)

    # Lower router ID wins a genuine collision and retains its initiator state.
    assert runtime._resolve_simultaneous_rekey("router-b") is False
    assert b"local" in runtime.pending
    assert dropped[-1] == ("NLS_REKEY_SIMULTANEOUS_LOST", "D:M1")

    # If the peer's M1 was accepted first, suppress a duplicate/parallel M1 and
    # keep the responder state; it must also block a second local start().
    runtime.pending = {
        b"remote": {"role": "D", "rekey": True, "peer_id": "router-b"},
    }
    assert runtime._resolve_simultaneous_rekey("router-b") is False
    assert list(runtime.pending) == [b"remote"]

    # Higher router ID abandons its own initiator state and accepts the winner.
    runtime.owner.cfg.router_id = "router-b"
    runtime.pending = {
        b"local": {"role": "S", "rekey": True, "peer_id": "router-a"},
    }
    assert runtime._resolve_simultaneous_rekey("router-a") is True
    assert not runtime.pending


def test_handshake_rate_limits_are_independent_and_bounded(monkeypatch):
    from types import SimpleNamespace

    from nls.v2_runtime import HandshakeV2

    runtime = HandshakeV2.__new__(HandshakeV2)
    runtime.owner = SimpleNamespace(
        cfg=SimpleNamespace(bind_interface=""),
    )
    runtime.buckets = {}
    runtime.prefix_buckets = {}
    runtime.interface_buckets = {}
    runtime.global_bucket = (500.0, 100.0)
    runtime._bucket_cleanup_at = 1000.0

    # Per-/64 controls remain effective when source addresses rotate.
    assert all(
        runtime._allow_source((f"2001:db8:1::{index + 1}", 40000), "eth0")
        for index in range(40)
    )
    assert not runtime._allow_source(("2001:db8:1::100", 40000), "eth0")

    # An independent ingress-interface bucket limits aggregate traffic from
    # many distinct /64s; the other interface has its own budget.
    runtime = HandshakeV2.__new__(HandshakeV2)
    runtime.owner = SimpleNamespace(cfg=SimpleNamespace(bind_interface=""))
    runtime.buckets = {}
    runtime.prefix_buckets = {}
    runtime.interface_buckets = {}
    runtime.global_bucket = (500.0, 100.0)
    runtime._bucket_cleanup_at = 1000.0
    for index in range(301):
        address = f"2001:{index + 1:x}::1"
        if index < 40:
            # Each source prefix has its own limit, so spread addresses over
            # unique /64s while keeping the exact-source limiter irrelevant.
            address = f"2001:{index + 1:x}:1::1"
        allowed = runtime._allow_source((address, 40000), "eth0")
        if not allowed:
            break
    assert not allowed
    assert runtime._allow_source(("2001:fffe:1::1", 40000), "eth1")

    # Attacker-controlled keys cannot grow without bound, even if the
    # rate limiter is presented with a pre-existing oversized table.
    now = __import__("time").monotonic()
    runtime.buckets.update({f"2001:{index + 1:x}::1": (1.0, now) for index in range(5000)})
    runtime.prefix_buckets.update({f"2001:{index + 1:x}::/64": (1.0, now) for index in range(5000)})
    runtime.interface_buckets.update({f"eth{index}": (1.0, now) for index in range(5000)})
    runtime._bucket_cleanup_at = 0.0
    runtime._prune_buckets(now)
    assert len(runtime.buckets) <= 4096
    assert len(runtime.prefix_buckets) <= 4096
    assert len(runtime.interface_buckets) <= 4096
