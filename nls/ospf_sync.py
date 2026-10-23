"""Trust-gated conversion between the NLS registry and FRR OSPFv2 opaque LSAs.

This module contains the security boundary used by a synchronizer: local registry
records are exported only in the canonical schema, peer records are checked
against the current Router-CA directory, and accepted records never install FIB
routes. The optional worker is disabled by default and requires explicit
administrator enablement.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import os
import re
import select
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import ca_client, identity, lsdb
from .ospf_opaque import FRROSPFv2OpaqueAdapter, OSPFAPIError, encode_record

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
        router_id.encode("utf-8") + bytes([0]) + vip.encode("ascii")
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
        except Exception:
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


class OSPFRegistrySynchronizer:
    """Synchronize local authenticated bindings and receive trusted peer bindings."""

    def __init__(
        self,
        adapter: FRROSPFv2OpaqueAdapter,
        *,
        local_router_id: str,
        ospf_router_id: str,
        private_key,
        settings,
    ):
        self.adapter = adapter
        self.local_router_id = local_router_id
        self.ospf_router_id = str(ipaddress.IPv4Address(ospf_router_id))
        self.private_key = private_key
        self.settings = settings
        self.verify = router_ca_verifier(settings)
        self.advertised = {}
        self.withdrawn = {}

    def _sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def local_identity_is_active(self):
        """Re-check local Router-CA trust so revocation/staleness stops origination."""
        try:
            if ca_client.directory_freshness(self.settings) < 0:
                return False
            if (
                getattr(self.settings, "trust_mode", "ca") != "offline"
                and ca_client.heartbeat_freshness(self.settings) < 0
            ):
                return False
            record = ca_client.cached_record(self.local_router_id, self.settings)
            return (
                record.get("router_id") == self.local_router_id
                and record.get("status") == "ACTIVE"
                and type(record.get("valid_until")) is int
                and record["valid_until"] > int(time.time())
                and record.get("ed25519_public_key") == identity.public_key_b64(self.private_key)
                and not ca_client.is_revoked(
                    str(record.get("certificate_serial", "")), self.settings
                )
            )
        except Exception:
            return False

    def sync_local_snapshot(self, *, now=None):
        """Originate changed local records and signed withdrawals for removed rows."""
        current_time = time.time() if now is None else float(now)
        local_records = [
            record for record in lsdb.export_records(now=current_time)
            if record.get("router_id") == self.local_router_id
        ]
        encoded = encode_registry_snapshot(
            local_records,
            ospf_router_id=self.ospf_router_id,
            sign=self._sign,
        )
        current = {}
        for opaque_id, payload in encoded:
            record = next(
                item for item in local_records
                if opaque_id_for_record(item) == opaque_id
            )
            current[opaque_id] = (record, payload)

        # Publish a signed WITHDRAWN record before flushing the LSA. Receivers
        # retain a persistent high-water mark, so an old signed update cannot
        # recreate the binding after the withdrawal has removed its LSDB row.
        for opaque_id, (old_record, _) in list(self.advertised.items()):
            if opaque_id in current:
                continue
            expiry = min(float(old_record["expires_at"]), current_time + 300.0)
            if expiry <= current_time:
                self.adapter.delete(opaque_id)
                self.advertised.pop(opaque_id, None)
                continue
            withdrawn_record = dict(old_record, state="WITHDRAWN", expires_at=expiry)
            _, payload = encode_registry_record(
                withdrawn_record,
                ospf_router_id=self.ospf_router_id,
                sign=self._sign,
            )
            self.adapter.originate(opaque_id, payload)
            self.withdrawn[opaque_id] = (withdrawn_record, payload, expiry)
            self.advertised.pop(opaque_id, None)

        for opaque_id, (record, payload) in current.items():
            old_withdrawal = self.withdrawn.get(opaque_id)
            if old_withdrawal is not None:
                old_record = old_withdrawal[0]
                if record["session_id"] == old_record["session_id"]:
                    # A withdrawn session is never reactivated, even if a later
                    # directory generation arrives. A new session requires a new vIP.
                    continue
                raise ValueError("local vIP was reassigned while its withdrawal is active")
            old = self.advertised.get(opaque_id)
            if old is None or old[1] != payload:
                self.adapter.originate(opaque_id, payload)
            self.advertised[opaque_id] = (record, payload)

        for opaque_id, (_, _, expiry) in list(self.withdrawn.items()):
            if current_time >= expiry:
                self.adapter.delete(opaque_id)
                self.withdrawn.pop(opaque_id, None)

    def receive_one(self):
        """Process one queued FRR event, applying only Router-CA-verified records."""
        def accept(record):
            if record["router_id"] == self.local_router_id:
                # Do not import our own LSA back into the local registry.
                return True
            accept_verified_record(
                record, authenticated_router_id=record["router_id"]
            )
            return True

        try:
            return self.adapter.receive_event(self.verify, accept)
        except OSPFAPIError as exc:
            if "unsigned NLS LSA deletion" in str(exc):
                logging.warning("Ignored unsigned OSPF NLS LSA flush")
                return None
            logging.warning("Rejected OSPF NLS event (%s)", type(exc).__name__)
            return None
        except Exception as exc:
            logging.warning("Rejected OSPF NLS record (%s)", type(exc).__name__)
            return None

    def run(self, *, poll_interval=1.0, stop_event=None):
        """Run until stop_event is set; registration and trust setup are explicit."""
        stop_event = stop_event or threading.Event()
        self.adapter.register()
        next_trust_check = 0.0
        local_trusted = False
        while not stop_event.is_set():
            now_mono = time.monotonic()
            if now_mono >= next_trust_check:
                local_trusted = self.local_identity_is_active()
                next_trust_check = now_mono + 5.0
                if not local_trusted:
                    logging.error("Local Router-CA identity is stale, revoked, or mismatched; pausing NLS origination")
                    self.advertised.clear()
            if local_trusted:
                self.sync_local_snapshot()
            async_socket = self.adapter._async
            if async_socket is not None:
                readable, _, _ = select.select([async_socket], [], [], poll_interval)
                if readable:
                    self.receive_one()
            else:
                stop_event.wait(poll_interval)


def _detect_ospf_router_id(pathspace=None):
    command = ["vtysh"]
    if pathspace:
        command.extend(["-N", pathspace])
    command.extend(["-c", "show ip ospf"])
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=5, check=True
    )
    match = re.search(r"Router ID:\s*([0-9.]+)", result.stdout)
    if not match:
        raise RuntimeError("FRR did not report an OSPFv2 router ID")
    return str(ipaddress.IPv4Address(match.group(1)))


def main():
    """Run the optional OSPFv2 sync worker; it is disabled unless explicitly enabled."""
    if os.environ.get("NLS_OSPF_SYNC_ENABLED") != "1":
        logging.info("NLS OSPF synchronization is disabled")
        return 0

    from . import config

    cfg = config.load()
    if not cfg.enabled:
        raise RuntimeError("NLS must be enabled before OSPF registry synchronization")
    settings_path = (
        os.environ.get("NLS_ROUTER_CA_CONFIG")
        or os.environ.get(
            "NLSXNETOS_ROUTER_CA_CLIENT_CONFIG",
            "/etc/nlsxnetos/router-ca-client.yaml",
        )
    )
    settings = ca_client.ClientSettings.load(settings_path)
    if settings.router_id != cfg.router_id:
        raise RuntimeError("Router-CA client identity does not match NLS router identity")
    if ca_client.directory_freshness(settings) < 0:
        raise RuntimeError("Router-CA directory is not fresh")
    if settings.trust_mode != "offline" and ca_client.heartbeat_freshness(settings) < 0:
        raise RuntimeError("Router-CA heartbeat is not fresh")

    key_path = Path(cfg.identity_key)
    private_raw = key_path.read_bytes()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if len(private_raw) != 32:
        raise ValueError("local Ed25519 identity key has invalid length")
    private_key = Ed25519PrivateKey.from_private_bytes(private_raw)
    local_record = ca_client.cached_record(cfg.router_id, settings)
    if (
        local_record.get("status") != "ACTIVE"
        or type(local_record.get("valid_until")) is not int
        or local_record["valid_until"] <= int(time.time())
        or local_record.get("ed25519_public_key") != identity.public_key_b64(private_key)
        or ca_client.is_revoked(str(local_record.get("certificate_serial", "")), settings)
    ):
        raise RuntimeError("local Router-CA identity is not active or does not match its key")

    ospf_router_id = os.environ.get("NLS_OSPF_ROUTER_ID") or _detect_ospf_router_id(
        os.environ.get("NLS_OSPF_VTYSH_PATHSPACE")
    )
    adapter = FRROSPFv2OpaqueAdapter(
        host=os.environ.get("NLS_OSPF_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("NLS_OSPF_API_PORT", "2607")),
        area_id=os.environ.get("NLS_OSPF_AREA_ID", "0.0.0.0"),
        opaque_type=int(os.environ.get("NLS_OSPF_OPAQUE_TYPE", "250")),
        timeout=5.0,
    )
    sync = OSPFRegistrySynchronizer(
        adapter,
        local_router_id=cfg.router_id,
        ospf_router_id=ospf_router_id,
        private_key=private_key,
        settings=settings,
    )
    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    try:
        sync.run(stop_event=stop_event)
    finally:
        adapter.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
