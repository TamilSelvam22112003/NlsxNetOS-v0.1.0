"""Trust-gated conversion between the NLS registry and FRR OSPFv2 opaque LSAs.

This module contains the security boundary used by a synchronizer: local registry
records are exported only in the canonical schema, peer records are checked
against the current Router-CA directory, and accepted records never install FIB
routes. It deliberately does not start a background thread or enable OSPF by
itself; runtime activation must be explicit in daemon configuration.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import time
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import ca_client, lsdb
from .ospf_opaque import encode_record

_REGISTRY_FIELDS = {
    "record_version", "record_type", "vip", "original_ip", "router_id",
    "identity_public_key", "source_token", "send_token", "local_original_ip",
    "session_id", "record_seq", "state", "expires_at",
}


def opaque_id_for_record(record: dict) -> int:
    """Return a stable non-zero 24-bit ID for a router/vIP binding."""
    if not isinstance(record, dict):
        raise ValueError("NLS registry record must be an object")
    router_id = record.get("router_id")
    vip = str(ipaddress.IPv6Address(record.get("vip")))
    if not isinstance(router_id, str) or not router_id:
        raise ValueError("NLS registry router identity is required")
    digest = hashlib.sha256(
        router_id.encode("utf-8") + b"\\x00" + vip.encode("ascii")
    ).digest()
    opaque_id = int.from_bytes(digest[:3], "big")
    return opaque_id or 1


def encode_registry_record(
    record: dict,
    *,
    ospf_router_id: str,
    sign: Callable[[bytes], bytes],
) -> tuple[int, bytes]:
    """Encode one canonical LSDB export record as a signed OSPF payload."""
    if not isinstance(record, dict) or set(record) != _REGISTRY_FIELDS:
        raise ValueError("NLS registry export has an unexpected field set")
    ospf_id = str(ipaddress.IPv4Address(ospf_router_id))
    wire_record = dict(record, ospf_router_id=ospf_id)
    return opaque_id_for_record(record), encode_record(wire_record, sign)


def encode_registry_snapshot(
    records: list[dict],
    *,
    ospf_router_id: str,
    sign: Callable[[bytes], bytes],
) -> list[tuple[int, bytes]]:
    """Encode a deterministic snapshot and fail closed on opaque-ID collision."""
    result = []
    seen = set()
    for record in records:
        opaque_id, payload = encode_registry_record(
            record, ospf_router_id=ospf_router_id, sign=sign
        )
        if opaque_id in seen:
            raise ValueError("NLS OSPF opaque-ID collision in registry snapshot")
        seen.add(opaque_id)
        result.append((opaque_id, payload))
    return sorted(result, key=lambda item: item[0])


def router_ca_verifier(settings):
    """Build a fail-closed signature callback backed by the verified Router-CA cache.

    The returned callback is compatible with FRROSPFv2OpaqueAdapter.decode_record.
    A public key supplied by an LSA is never trusted unless it exactly matches
    the ACTIVE, unexpired Router-CA directory record for that router identity.
    """
    def verify(router_id, identity_public_key, signed_bytes, signature):
        try:
            if ca_client.directory_freshness(settings) < 0:
                return False
            if (
                getattr(settings, "trust_mode", "ca") != "offline"
                and ca_client.heartbeat_freshness(settings) < 0
            ):
                return False
            record = ca_client.cached_record(router_id, settings)
            now = int(time.time())
            if (
                record.get("router_id") != router_id
                or record.get("status") != "ACTIVE"
                or type(record.get("valid_until")) is not int
                or record["valid_until"] <= now
                or record.get("ed25519_public_key") != identity_public_key
                or ca_client.is_revoked(str(record.get("certificate_serial", "")), settings)
            ):
                return False
            raw_key = base64.b64decode(identity_public_key.encode("ascii"), validate=True)
            if len(raw_key) != 32:
                return False
            Ed25519PublicKey.from_public_bytes(raw_key).verify(signature, signed_bytes)
            return True
        except (InvalidSignature, ValueError, TypeError, OSError, RuntimeError):
            return False

    return verify


def accept_verified_record(record: dict, *, authenticated_router_id: str):
    """Apply an already signature-verified record to the local LSDB registry."""
    if not isinstance(record, dict):
        raise ValueError("NLS OSPF record must be an object")
    if record.get("router_id") != authenticated_router_id:
        raise ValueError("NLS OSPF identity does not match verified Router-CA identity")
    canonical = dict(record)
    canonical.pop("ospf_router_id", None)
    return lsdb.apply_routing_record(
        canonical, authenticated_router_id=authenticated_router_id
    )
