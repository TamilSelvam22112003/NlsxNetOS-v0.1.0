"""FRRouting OSPFv2 area-opaque-LSA adapter for authenticated NLS metadata.

This module never installs routes. OSPFv2 opaque LSAs carry signed NLS registry
records only; receiving an LSA is not authorization to install a kernel route.
The FRR OSPF API is a privileged, unauthenticated local control interface, so
connections are restricted to loopback by default.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import math
import socket
import struct
import time
from typing import Callable

_API_HEADER = struct.Struct(">BBHL")
_LSA_HEADER = struct.Struct(">HBBIILHH")
_REPLY = 10
_READY_NOTIFY = 11
_LSA_UPDATE_NOTIFY = 12
_LSA_DELETE_NOTIFY = 13
_REGISTER_OPAQUE_TYPE = 1
_ORIGINATE_REQUEST = 5
_DELETE_REQUEST = 6
_OPAQUE_AREA = 10
_API_VERSION = 1
_MAX_RECORD_BYTES = 4096
_MAX_TTL_SECONDS = 300
_RECORD_FIELDS = {
    "record_version", "record_type", "router_id", "original_ip", "vip",
    "source_token", "session_id", "record_seq", "state", "expires_at", "key_id",
}
_STATES = {"ESTABLISHED", "OVERLAP", "WITHDRAWN"}


class OSPFAPIError(RuntimeError):
    """FRR OSPF API connection or request failed."""


def _ipv4(value: str, field: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError(f"{field} must be an IPv4 address") from exc


def _ipv6(value: str, field: str) -> str:
    try:
        return str(ipaddress.IPv6Address(value))
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError(f"{field} must be an IPv6 address") from exc


def _canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def encode_record(record: dict, sign: Callable[[bytes], bytes]) -> bytes:
    """Validate and sign one exact-schema NLS binding record.

    sign must use the local router identity's Ed25519 private key. The matching
    public key must be trusted through the Router-CA verification callback on
    every receiving router.
    """
    if not isinstance(record, dict) or set(record) != _RECORD_FIELDS:
        raise ValueError("NLS routing record has an unexpected field set")
    if (isinstance(record["record_version"], bool) or not isinstance(record["record_version"], int)
            or record["record_version"] != 1 or record["record_type"] != "nls_vip_binding"):
        raise ValueError("unsupported NLS routing record version/type")
    normalized = dict(record)
    normalized["router_id"] = _ipv4(record["router_id"], "router_id")
    normalized["original_ip"] = _ipv6(record["original_ip"], "original_ip")
    normalized["vip"] = _ipv6(record["vip"], "vip")
    normalized["source_token"] = _ipv6(record["source_token"], "source_token")
    if not isinstance(record["session_id"], str) or not record["session_id"] or len(record["session_id"]) > 128:
        raise ValueError("session_id must be a non-empty string of at most 128 characters")
    if isinstance(record["record_seq"], bool) or not isinstance(record["record_seq"], int) or not 1 <= record["record_seq"] <= 0x7FFFFFFF:
        raise ValueError("record_seq must be a positive 31-bit integer")
    if not isinstance(record["state"], str) or record["state"] not in _STATES:
        raise ValueError("invalid NLS binding state")
    if not isinstance(record["key_id"], str) or not record["key_id"] or len(record["key_id"]) > 128:
        raise ValueError("key_id must be a non-empty string of at most 128 characters")
    try:
        expiry = float(record["expires_at"])
    except (TypeError, ValueError) as exc:
        raise ValueError("expires_at must be a Unix timestamp") from exc
    now = time.time()
    if not math.isfinite(expiry) or expiry <= now or expiry > now + _MAX_TTL_SECONDS:
        raise ValueError("expires_at must be in the next 300 seconds")
    normalized["expires_at"] = expiry
    signed = _canonical_json(normalized)
    signature = sign(signed)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("sign callback must return a 64-byte Ed25519 signature")
    envelope = dict(normalized, signature=base64.b64encode(signature).decode("ascii"))
    encoded = _canonical_json(envelope)
    if len(encoded) > _MAX_RECORD_BYTES:
        raise ValueError("NLS routing record exceeds the 4096-byte payload limit")
    return encoded


def decode_record(
    payload: bytes,
    verify: Callable[[str, str, bytes, bytes], bool],
    *,
    advertising_router: str,
    now: float | None = None,
) -> dict:
    """Verify an LSA payload against the authoritative Router-CA identity.

    verify(router_id, key_id, canonical_signed_bytes, signature) must perform a
    fresh trust decision against the authoritative registry; a payload never
    supplies its own trusted public key.
    """
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_RECORD_BYTES:
        raise ValueError("invalid NLS routing payload size")
    try:
        envelope = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid NLS routing payload encoding") from exc
    if not isinstance(envelope, dict) or set(envelope) != _RECORD_FIELDS | {"signature"}:
        raise ValueError("NLS routing payload has an unexpected field set")
    record = {key: envelope[key] for key in _RECORD_FIELDS}
    if (isinstance(record["record_version"], bool) or not isinstance(record["record_version"], int)
            or record["record_version"] != 1 or record["record_type"] != "nls_vip_binding"):
        raise ValueError("unsupported NLS routing record version/type")
    record["router_id"] = _ipv4(record["router_id"], "router_id")
    if record["router_id"] != _ipv4(advertising_router, "advertising_router"):
        raise ValueError("LSA advertising router does not match signed router_id")
    record["original_ip"] = _ipv6(record["original_ip"], "original_ip")
    record["vip"] = _ipv6(record["vip"], "vip")
    record["source_token"] = _ipv6(record["source_token"], "source_token")
    if not isinstance(record["session_id"], str) or not record["session_id"] or len(record["session_id"]) > 128:
        raise ValueError("invalid session_id")
    if isinstance(record["record_seq"], bool) or not isinstance(record["record_seq"], int) or not 1 <= record["record_seq"] <= 0x7FFFFFFF:
        raise ValueError("invalid record_seq")
    if not isinstance(record["state"], str) or record["state"] not in _STATES:
        raise ValueError("invalid NLS binding state")
    if not isinstance(record["key_id"], str) or not record["key_id"] or len(record["key_id"]) > 128:
        raise ValueError("invalid key_id")
    try:
        expiry = float(record["expires_at"])
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid expiry or signature encoding") from exc
    current = time.time() if now is None else float(now)
    if not math.isfinite(expiry) or expiry <= current or expiry > current + _MAX_TTL_SECONDS:
        raise ValueError("NLS routing record is expired or has excessive lifetime")
    if len(signature) != 64:
        raise ValueError("invalid Ed25519 signature length")
    record["expires_at"] = expiry
    if verify(record["router_id"], record["key_id"], _canonical_json(record), signature) is not True:
        raise ValueError("NLS routing record signature or Router-CA trust validation failed")
    return record


def pack_api_message(message_type: int, sequence: int, payload: bytes) -> bytes:
    """Encode one FRR OSPF API v1 frame."""
    if not 0 <= message_type <= 255 or not 1 <= sequence <= 0x7FFFFFFF:
        raise ValueError("invalid OSPF API message type or sequence")
    if len(payload) > 0xFFFF:
        raise ValueError("OSPF API message is too large")
    return _API_HEADER.pack(_API_VERSION, message_type, len(payload), sequence) + payload


def unpack_api_header(header: bytes) -> tuple[int, int, int, int]:
    if len(header) != _API_HEADER.size:
        raise ValueError("invalid OSPF API header size")
    version, message_type, length, sequence = _API_HEADER.unpack(header)
    if version != _API_VERSION:
        raise OSPFAPIError(f"unsupported FRR OSPF API version {version}")
    return version, message_type, length, sequence


class FRROSPFv2OpaqueAdapter:
    """Minimal client for FRR's supported OSPFv2 Opaque-LSA API.

    Only area-local opaque LSAs are used. This does not implement OSPFv3,
    route installation, or cryptographic trust by itself.
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 2607,
        area_id: str = "0.0.0.0",
        opaque_type: int = 250,
        timeout: float = 5.0,
    ):
        address = ipaddress.ip_address(host)
        if not address.is_loopback:
            raise ValueError("FRR OSPF API must be accessed over loopback only")
        if not 1 <= port <= 65534 or not 1 <= opaque_type <= 255:
            raise ValueError("invalid OSPF API port or opaque type")
        self.host = str(address)
        self.port = port
        self.area_id = _ipv4(area_id, "area_id")
        self.opaque_type = opaque_type
        self.timeout = timeout
        self._sync: socket.socket | None = None
        self._async: socket.socket | None = None
        self._sequence = 1
        self._registered = False

    @staticmethod
    def _read_exact(sock: socket.socket, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            part = sock.recv(size - len(chunks))
            if not part:
                raise OSPFAPIError("FRR OSPF API connection closed")
            chunks.extend(part)
        return bytes(chunks)

    def _read_frame(self, sock: socket.socket) -> tuple[int, int, bytes]:
        header = self._read_exact(sock, _API_HEADER.size)
        _, message_type, length, sequence = unpack_api_header(header)
        return message_type, sequence, self._read_exact(sock, length) if length else b""

    def connect(self) -> None:
        if self._sync is not None:
            return
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sync = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(self.timeout)
        sync.settimeout(self.timeout)
        try:
            # FRR opens the asynchronous callback channel to local-port + 1.
            bound = False
            for local_port in range(49152, 65534, 2):
                try:
                    sync.bind((self.host, local_port))
                    listener.bind((self.host, local_port + 1))
                    bound = True
                    break
                except OSError:
                    sync.close()
                    listener.close()
                    sync = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sync.settimeout(self.timeout)
                    listener.settimeout(self.timeout)
            if not bound:
                raise OSPFAPIError("could not reserve consecutive local OSPF API ports")
            listener.listen(1)
            sync.connect((self.host, self.port))
            async_sock, _ = listener.accept()
            async_sock.settimeout(self.timeout)
            self._sync, self._async = sync, async_sock
        except Exception:
            sync.close()
            raise
        finally:
            listener.close()

    def close(self) -> None:
        for sock in (self._sync, self._async):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._sync = self._async = None
        self._registered = False

    def _request(self, message_type: int, payload: bytes) -> None:
        if self._sync is None:
            raise OSPFAPIError("connect to FRR OSPF API first")
        sequence = self._sequence
        self._sequence = 1 if sequence >= 0x7FFFFFFF else sequence + 1
        self._sync.sendall(pack_api_message(message_type, sequence, payload))
        reply_type, reply_sequence, reply = self._read_frame(self._sync)
        if reply_type != _REPLY or reply_sequence != sequence or len(reply) != 4:
            raise OSPFAPIError("unexpected FRR OSPF API reply")
        code = struct.unpack(">bxxx", reply)[0]
        if code:
            raise OSPFAPIError(f"FRR OSPF API request failed with code {code}")

    def register(self) -> None:
        """Register the experimental opaque type and wait for FRR readiness."""
        self.connect()
        self._request(_REGISTER_OPAQUE_TYPE, struct.pack(">BBxx", _OPAQUE_AREA, self.opaque_type))
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            assert self._async is not None
            old_timeout = self._async.gettimeout()
            self._async.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                message_type, _, body = self._read_frame(self._async)
            except socket.timeout as exc:
                raise OSPFAPIError("timed out waiting for FRR OSPF opaque-LSA readiness") from exc
            finally:
                self._async.settimeout(old_timeout)
            if message_type == _READY_NOTIFY and len(body) >= 8:
                lsa_type, opaque_type = struct.unpack(">BB", body[:2])
                area = str(ipaddress.IPv4Address(struct.unpack(">I", body[4:8])[0]))
                if lsa_type == _OPAQUE_AREA and opaque_type == self.opaque_type and area == self.area_id:
                    self._registered = True
                    return
        raise OSPFAPIError("FRR did not report this area opaque-LSA type ready")

    def originate(self, opaque_id: int, payload: bytes) -> None:
        """Originate/update a signed NLS record; never changes the kernel FIB."""
        if not self._registered:
            raise OSPFAPIError("opaque type must be registered and ready before origination")
        if not 1 <= opaque_id <= 0xFFFFFF:
            raise ValueError("opaque_id must fit in 24 bits and be non-zero")
        if not payload or len(payload) > _MAX_RECORD_BYTES:
            raise ValueError("invalid signed NLS payload size")
        area = int(ipaddress.IPv4Address(self.area_id))
        lsid = (self.opaque_type << 24) | opaque_id
        lsa_length = _LSA_HEADER.size + len(payload)
        lsa_header = _LSA_HEADER.pack(0, 0, _OPAQUE_AREA, lsid, 0, 0, 0, lsa_length)
        body = struct.pack(">II", 0, area) + lsa_header + payload
        self._request(_ORIGINATE_REQUEST, body)

    def delete(self, opaque_id: int) -> None:
        """Flush a local LSA. Receivers must not trust this alone as a signed withdrawal."""
        if not self._registered:
            raise OSPFAPIError("opaque type must be registered and ready before deletion")
        if not 1 <= opaque_id <= 0xFFFFFF:
            raise ValueError("opaque_id must fit in 24 bits and be non-zero")
        area = int(ipaddress.IPv4Address(self.area_id))
        body = struct.pack(">IBBxBL", area, _OPAQUE_AREA, self.opaque_type, 0, opaque_id)
        self._request(_DELETE_REQUEST, body)

    def receive_record(
        self,
        verify: Callable[[str, str, bytes, bytes], bool],
        accept_record: Callable[[dict], bool],
    ) -> dict:
        """Receive and authenticate one area-opaque LSA update notification.

        LSA deletion notifications are deliberately rejected as an authorization
        signal: the sender must flood a signed WITHDRAWN record first. The
        accept_record callback must atomically enforce persistent monotonic
        record_seq, session lifecycle, Router-CA status, and local registry updates. The
        accept_record callback must atomically enforce persistent monotonic
        record_seq, session lifecycle, Router-CA status, and local registry updates.
        """
        if self._async is None:
            raise OSPFAPIError("connect to FRR OSPF API first")
        while True:
            message_type, _, body = self._read_frame(self._async)
            if message_type == _LSA_DELETE_NOTIFY:
                raise OSPFAPIError("unsigned LSA deletion is not an authorized NLS withdrawal")
            if message_type != _LSA_UPDATE_NOTIFY:
                continue
            prefix_size = struct.calcsize(">IIBxxx")
            if len(body) < prefix_size + _LSA_HEADER.size:
                raise OSPFAPIError("truncated FRR LSA update notification")
            _, area, _ = struct.unpack(">IIB", body[:9])
            header_start = prefix_size
            header = _LSA_HEADER.unpack(body[header_start:header_start + _LSA_HEADER.size])
            _, _, lsa_type, lsid, adv_router, _, _, length = header
            payload = body[header_start + _LSA_HEADER.size:]
            if lsa_type != _OPAQUE_AREA or (lsid >> 24) != self.opaque_type or area != int(ipaddress.IPv4Address(self.area_id)):
                continue
            if length != _LSA_HEADER.size + len(payload):
                raise OSPFAPIError("LSA declared length does not match received payload")
            record = decode_record(
                payload, verify,
                advertising_router=str(ipaddress.IPv4Address(adv_router)),
            )
            if accept_record(record) is not True:
                raise OSPFAPIError("signed NLS record rejected as stale or unauthorized")
            return record
