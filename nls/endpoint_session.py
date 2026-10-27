"""Forward-secret endpoint session establishment and NLE3 data protection.

NLEH performs an authenticated ephemeral X25519 handshake using Router-CA-pinned
Ed25519 identities. NLE3 carries only an opaque session token, sequence, nonce,
length, and AEAD ciphertext; original IP addresses and transport/application
metadata stay in the ciphertext. Intermediate relays must forward NLEH/NLE3
bytes as opaque endpoint content inside NLR1.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Mapping

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import b64, unb64
from .replay import ReplayWindow

CONTROL_MAGIC = b"NLEH"
CONTROL_VERSION = 1
CONTROL_INIT = 1
CONTROL_RESPONSE = 2
CONTROL_FRAME = struct.Struct("!4sBBH")
MAX_CONTROL_BYTES = 8192
DATA_MAGIC = b"NLE3"
DATA_VERSION = 1
DATA_HEADER = struct.Struct("!4sB16sQ12sI")
MAX_ENDPOINT_DATAGRAM = 65507
KEY_INFO = b"NLS-endpoint-session-v1"
SIGNING_PREFIX = b"NLEH1-ENDPOINT-HANDSHAKE|"


class EndpointSessionError(ValueError):
    """Raised for invalid endpoint handshakes, sessions, or data packets."""


@dataclass
class EndpointSession:
    """Directional endpoint traffic keys derived from a fresh X25519 exchange."""

    session_id: bytes
    peer_identity: bytes
    tx_key: bytes
    rx_key: bytes
    tx_sequence: int = 0
    rx_window: ReplayWindow = field(default_factory=ReplayWindow)
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


@dataclass
class PendingEndpointHandshake:
    """Initiator's ephemeral private key and exact signed INIT transcript."""

    session_id: bytes
    ephemeral_private: X25519PrivateKey
    init_packet: bytes
    peer_identity: bytes
    created_at: float


def _raw_identity(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _raw_x25519(key: X25519PrivateKey | X25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, X25519PrivateKey) else key
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _signing_bytes(kind: int, obj: dict) -> bytes:
    unsigned = dict(obj)
    unsigned.pop("signature", None)
    return SIGNING_PREFIX + bytes([kind]) + b"|" + _canonical(unsigned)


def _sign(obj: dict, kind: int, private_key: Ed25519PrivateKey) -> dict:
    signed = dict(obj)
    signed["signature"] = b64(private_key.sign(_signing_bytes(kind, signed)))
    return signed


def _encode_control(kind: int, obj: dict) -> bytes:
    body = _canonical(obj)
    if len(body) > MAX_CONTROL_BYTES:
        raise EndpointSessionError("endpoint handshake message exceeds size limit")
    return CONTROL_FRAME.pack(CONTROL_MAGIC, CONTROL_VERSION, kind, len(body)) + body


def _decode_control(packet: bytes) -> tuple[int, dict]:
    if not isinstance(packet, bytes) or len(packet) < CONTROL_FRAME.size:
        raise EndpointSessionError("endpoint handshake frame is truncated")
    magic, version, kind, length = CONTROL_FRAME.unpack_from(packet)
    if magic != CONTROL_MAGIC or version != CONTROL_VERSION:
        raise EndpointSessionError("unsupported endpoint handshake version")
    if kind not in (CONTROL_INIT, CONTROL_RESPONSE):
        raise EndpointSessionError("unknown endpoint handshake message type")
    if length > MAX_CONTROL_BYTES or len(packet) != CONTROL_FRAME.size + length:
        raise EndpointSessionError("invalid endpoint handshake frame length")
    try:
        obj = json.loads(packet[CONTROL_FRAME.size:].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EndpointSessionError("invalid endpoint handshake JSON") from exc
    if not isinstance(obj, dict):
        raise EndpointSessionError("endpoint handshake body must be an object")
    return kind, obj


def _decode_b64_field(obj: dict, name: str, size: int) -> bytes:
    try:
        value = unb64(obj[name])
    except (KeyError, TypeError, ValueError) as exc:
        raise EndpointSessionError(f"invalid endpoint handshake field {name}") from exc
    if len(value) != size:
        raise EndpointSessionError(f"endpoint handshake field {name} must be {size} bytes")
    return value


def _check_time(value, *, max_clock_skew: int, now: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EndpointSessionError("endpoint handshake timestamp must be an integer")
    current = int(time.time()) if now is None else int(now)
    if max_clock_skew < 0 or abs(current - value) > max_clock_skew:
        raise EndpointSessionError("endpoint handshake timestamp outside allowed clock skew")
    return value


def _verify_signed(kind: int, obj: dict, key: Ed25519PublicKey) -> None:
    try:
        signature = unb64(obj["signature"])
        key.verify(signature, _signing_bytes(kind, obj))
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise EndpointSessionError("endpoint handshake signature verification failed") from exc


def _derive_keys(shared_secret: bytes, session_id: bytes, initiator_identity: bytes, responder_identity: bytes) -> tuple[bytes, bytes]:
    if not any(shared_secret):
        raise EndpointSessionError("invalid all-zero X25519 shared secret")
    salt = hashlib.sha256(
        b"NLEP1-TRANSCRIPT|" + session_id + initiator_identity + responder_identity
    ).digest()
    material = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=salt, info=KEY_INFO
    ).derive(shared_secret)
    return material[:32], material[32:]


def new_init(
    source_identity_key: Ed25519PrivateKey,
    target_identity: bytes,
    *,
    session_id: bytes | None = None,
    timestamp: int | None = None,
    nonce: bytes | None = None,
) -> tuple[bytes, PendingEndpointHandshake]:
    """Create a signed endpoint INIT; private ephemeral material remains local."""
    if not isinstance(source_identity_key, Ed25519PrivateKey):
        raise EndpointSessionError("source identity must be an Ed25519 private key")
    if not isinstance(target_identity, bytes) or len(target_identity) != 32:
        raise EndpointSessionError("target identity must be a 32-byte Ed25519 public key")
    sid = secrets.token_bytes(16) if session_id is None else session_id
    if not isinstance(sid, bytes) or len(sid) != 16:
        raise EndpointSessionError("endpoint session id must be 16 bytes")
    nonce_value = secrets.token_bytes(16) if nonce is None else nonce
    if not isinstance(nonce_value, bytes) or len(nonce_value) != 16:
        raise EndpointSessionError("endpoint handshake nonce must be 16 bytes")
    ephemeral = X25519PrivateKey.generate()
    src = _raw_identity(source_identity_key)
    obj = {
        "message": "init",
        "protocol_version": CONTROL_VERSION,
        "session_id": b64(sid),
        "source_identity": b64(src),
        "target_identity": b64(target_identity),
        "ephemeral_public_key": b64(_raw_x25519(ephemeral)),
        "timestamp": int(time.time()) if timestamp is None else int(timestamp),
        "nonce": b64(nonce_value),
    }
    packet = _encode_control(CONTROL_INIT, _sign(obj, CONTROL_INIT, source_identity_key))
    pending = PendingEndpointHandshake(sid, ephemeral, packet, target_identity, time.time())
    return packet, pending


def respond_to_init(
    packet: bytes,
    responder_identity_key: Ed25519PrivateKey,
    trusted_sources: Mapping[bytes, Ed25519PublicKey],
    *,
    max_clock_skew: int = 120,
    now: int | None = None,
) -> tuple[bytes, EndpointSession]:
    """Authenticate an INIT and return signed RESPONSE plus responder session keys."""
    kind, obj = _decode_control(packet)
    if kind != CONTROL_INIT or obj.get("message") != "init":
        raise EndpointSessionError("expected endpoint INIT")
    if obj.get("protocol_version") != CONTROL_VERSION:
        raise EndpointSessionError("unsupported endpoint handshake protocol version")
    source_identity = _decode_b64_field(obj, "source_identity", 32)
    target_identity = _decode_b64_field(obj, "target_identity", 32)
    if target_identity != _raw_identity(responder_identity_key):
        raise EndpointSessionError("endpoint INIT target identity mismatch")
    _check_time(obj.get("timestamp"), max_clock_skew=max_clock_skew, now=now)
    _decode_b64_field(obj, "nonce", 16)
    session_id = _decode_b64_field(obj, "session_id", 16)
    ephemeral_raw = _decode_b64_field(obj, "ephemeral_public_key", 32)
    source_key = trusted_sources.get(source_identity)
    if source_key is None:
        raise EndpointSessionError("endpoint INIT source identity is not trusted by Router-CA")
    _verify_signed(CONTROL_INIT, obj, source_key)

    ephemeral_private = X25519PrivateKey.generate()
    try:
        shared = ephemeral_private.exchange(X25519PublicKey.from_public_bytes(ephemeral_raw))
    except ValueError as exc:
        raise EndpointSessionError("invalid endpoint INIT X25519 public key") from exc
    initiator_tx, responder_tx = _derive_keys(
        shared, session_id, source_identity, target_identity
    )
    response_obj = {
        "message": "response",
        "protocol_version": CONTROL_VERSION,
        "session_id": b64(session_id),
        "source_identity": b64(target_identity),
        "target_identity": b64(source_identity),
        "ephemeral_public_key": b64(_raw_x25519(ephemeral_private)),
        "timestamp": int(time.time()) if now is None else int(now),
        "init_digest": hashlib.sha256(packet).hexdigest(),
    }
    response_packet = _encode_control(
        CONTROL_RESPONSE, _sign(response_obj, CONTROL_RESPONSE, responder_identity_key)
    )
    return response_packet, EndpointSession(
        session_id=session_id,
        peer_identity=source_identity,
        tx_key=responder_tx,
        rx_key=initiator_tx,
    )


def accept_response(
    packet: bytes,
    pending: PendingEndpointHandshake,
    source_identity_key: Ed25519PublicKey,
    local_identity_key: Ed25519PrivateKey,
    *,
    max_clock_skew: int = 120,
    now: int | None = None,
) -> EndpointSession:
    """Validate a response bound to the exact INIT transcript and derive initiator keys."""
    kind, obj = _decode_control(packet)
    if kind != CONTROL_RESPONSE or obj.get("message") != "response":
        raise EndpointSessionError("expected endpoint RESPONSE")
    if obj.get("protocol_version") != CONTROL_VERSION:
        raise EndpointSessionError("unsupported endpoint handshake protocol version")
    source_identity = _decode_b64_field(obj, "source_identity", 32)
    target_identity = _decode_b64_field(obj, "target_identity", 32)
    session_id = _decode_b64_field(obj, "session_id", 16)
    ephemeral_raw = _decode_b64_field(obj, "ephemeral_public_key", 32)
    if source_identity != _raw_identity(source_identity_key):
        raise EndpointSessionError("endpoint RESPONSE source identity mismatch")
    if target_identity != _raw_identity(local_identity_key):
        raise EndpointSessionError("endpoint RESPONSE target identity mismatch")
    if session_id != pending.session_id or pending.peer_identity != source_identity:
        raise EndpointSessionError("endpoint RESPONSE session binding mismatch")
    _check_time(obj.get("timestamp"), max_clock_skew=max_clock_skew, now=now)
    if obj.get("init_digest") != hashlib.sha256(pending.init_packet).hexdigest():
        raise EndpointSessionError("endpoint RESPONSE transcript mismatch")
    _verify_signed(CONTROL_RESPONSE, obj, source_identity_key)
    try:
        shared = pending.ephemeral_private.exchange(X25519PublicKey.from_public_bytes(ephemeral_raw))
    except ValueError as exc:
        raise EndpointSessionError("invalid endpoint RESPONSE X25519 public key") from exc
    initiator_tx, responder_tx = _derive_keys(
        shared, session_id, target_identity, source_identity
    )
    return EndpointSession(
        session_id=session_id,
        peer_identity=source_identity,
        tx_key=initiator_tx,
        rx_key=responder_tx,
    )


def _inner_destination(packet: bytes) -> str:
    if not isinstance(packet, bytes) or not packet:
        raise EndpointSessionError("endpoint payload must be non-empty bytes")
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            raise EndpointSessionError("IPv4 endpoint payload is truncated")
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            raise EndpointSessionError("invalid IPv4 endpoint header")
        return str(ipaddress.IPv4Address(packet[16:20]))
    if version == 6:
        if len(packet) < 40:
            raise EndpointSessionError("IPv6 endpoint payload is truncated")
        return str(ipaddress.IPv6Address(packet[24:40]))
    raise EndpointSessionError("unsupported endpoint IP version")


def seal_data(session: EndpointSession, packet: bytes, destination: str) -> bytes:
    """Seal one IP packet under the negotiated endpoint session traffic key."""
    try:
        address = ipaddress.ip_address(destination)
    except (ValueError, TypeError) as exc:
        raise EndpointSessionError("outer destination must be an IP literal") from exc
    if address.is_unspecified or address.is_multicast:
        raise EndpointSessionError("outer destination must be unicast")
    if _inner_destination(packet) != str(address):
        raise EndpointSessionError("inner destination does not match final endpoint")
    if session.tx_sequence < 0 or session.tx_sequence >= 2**64:
        raise EndpointSessionError("endpoint session sequence exhausted; rekey required")
    nonce = secrets.token_bytes(12)
    ciphertext_len = len(packet) + 16
    header = DATA_HEADER.pack(
        DATA_MAGIC, DATA_VERSION, session.session_id, session.tx_sequence,
        nonce, ciphertext_len,
    )
    ciphertext = AESGCM(session.tx_key).encrypt(nonce, packet, header)
    if len(header) + len(ciphertext) > MAX_ENDPOINT_DATAGRAM:
        raise EndpointSessionError("NLE3 endpoint datagram exceeds UDP payload limit")
    session.tx_sequence += 1
    return header + ciphertext


def open_data(
    packet: bytes,
    session: EndpointSession,
    expected_destination: str,
) -> dict:
    """Authenticate/decrypt NLE3, enforce replay window, and bind inner destination."""
    if not isinstance(packet, bytes) or len(packet) < DATA_HEADER.size + 16:
        raise EndpointSessionError("NLE3 endpoint datagram is truncated")
    try:
        magic, version, session_id, sequence, nonce, ciphertext_len = DATA_HEADER.unpack_from(packet)
    except struct.error as exc:
        raise EndpointSessionError("invalid NLE3 header") from exc
    if magic != DATA_MAGIC or version != DATA_VERSION:
        raise EndpointSessionError("unsupported NLE3 endpoint data version")
    if session_id != session.session_id:
        raise EndpointSessionError("NLE3 endpoint session token mismatch")
    if ciphertext_len != len(packet) - DATA_HEADER.size:
        raise EndpointSessionError("NLE3 ciphertext length mismatch")
    if not session.rx_window.can_accept(sequence):
        raise EndpointSessionError("NLE3 endpoint replay detected")
    try:
        plaintext = AESGCM(session.rx_key).decrypt(nonce, packet[DATA_HEADER.size:], packet[:DATA_HEADER.size])
    except InvalidTag as exc:
        raise EndpointSessionError("NLE3 endpoint AEAD authentication failed") from exc
    try:
        dest = ipaddress.ip_address(expected_destination)
    except (ValueError, TypeError) as exc:
        raise EndpointSessionError("expected destination must be an IP literal") from exc
    if dest.is_unspecified or dest.is_multicast or _inner_destination(plaintext) != str(dest):
        raise EndpointSessionError("NLE3 inner/outer destination mismatch")
    if not session.rx_window.mark(sequence):
        raise EndpointSessionError("NLE3 endpoint replay detected")
    session.last_seen = time.time()
    return {"session_id": session_id, "sequence": sequence, "payload": plaintext}


def inspect_control_packet(packet: bytes) -> tuple[int, dict]:
    """Decode a bounded NLEH control message for dispatch; caller still verifies trust."""
    return _decode_control(packet)


def data_session_id(packet: bytes) -> bytes:
    """Return the opaque NLE3 session id after validating its fixed header."""
    if not isinstance(packet, bytes) or len(packet) < DATA_HEADER.size + 16:
        raise EndpointSessionError("NLE3 endpoint datagram is truncated")
    try:
        magic, version, session_id, _sequence, _nonce, ciphertext_len = DATA_HEADER.unpack_from(packet)
    except struct.error as exc:
        raise EndpointSessionError("invalid NLE3 header") from exc
    if magic != DATA_MAGIC or version != DATA_VERSION:
        raise EndpointSessionError("unsupported NLE3 endpoint data version")
    if ciphertext_len != len(packet) - DATA_HEADER.size:
        raise EndpointSessionError("NLE3 ciphertext length mismatch")
    return session_id


def verify_control_packet(
    packet: bytes,
    expected_kind: int,
    trusted_identity_key: Ed25519PublicKey,
) -> dict:
    """Verify a NLEH message signature against the caller-selected Router-CA key."""
    kind, obj = _decode_control(packet)
    if kind != expected_kind:
        raise EndpointSessionError("unexpected endpoint handshake message kind")
    _verify_signed(kind, obj, trusted_identity_key)
    return obj
