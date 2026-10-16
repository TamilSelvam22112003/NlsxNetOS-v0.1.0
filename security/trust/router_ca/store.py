"""Verified Router-CA directory cache. Unsigned YAML is never a trust source."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

import cbor2
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import RouterCAEntry

CACHE_PATH = Path(os.environ.get(
    "NLSXNETOS_ROUTER_CA_DIRECTORY",
    "/var/lib/nlsxnetos/security/router-directory.json",
))
CLIENT_CONFIG = Path(os.environ.get(
    "NLSXNETOS_ROUTER_CA_CLIENT_CONFIG",
    "/etc/nlsxnetos/router-ca-client.yaml",
))
DOMAIN = b"NLS-DIR-v1"


def _cache_path() -> Path:
    override = os.environ.get("NLSXNETOS_ROUTER_CA_DIRECTORY")
    if override:
        return Path(override)
    try:
        raw = yaml.safe_load(CLIENT_CONFIG.read_text(encoding="utf-8")) or {}
        cfg = raw.get("router_ca", raw)
        if cfg.get("directory_file"):
            return Path(cfg["directory_file"])
    except (OSError, ValueError, TypeError):
        pass
    return CACHE_PATH


def _stale_grace_seconds() -> int:
    for config_path in (Path("/etc/nlsxnetos/nls.yaml"), CLIENT_CONFIG):
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            nls_cfg = raw.get("nls", raw)
            value = nls_cfg.get("stale_grace_seconds")
            if value is None:
                value = raw.get("router_ca", raw).get("stale_grace_seconds", 0)
            return min(max(int(value), 0), 600)
        except (OSError, ValueError, TypeError):
            continue
    return 0


def _pinned_key() -> bytes:
    try:
        raw = yaml.safe_load(CLIENT_CONFIG.read_text(encoding="utf-8")) or {}
        cfg = raw.get("router_ca", raw)
        key = base64.b64decode(str(cfg["server_public_key"]).encode("ascii"), validate=True)
        if len(key) != 32:
            raise ValueError("pinned control identity must be 32 bytes")
        return key
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Router-CA control identity pin is unavailable; trust cache rejected") from exc


def _verify(envelope: dict, pinned: bytes) -> dict:
    try:
        if envelope.get("domain") != "NLS-DIR-v1" or envelope.get("encoding") != "canonical-cbor":
            raise ValueError("unsupported signature envelope")
        signer = base64.b64decode(envelope["signer_public_key"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        payload = envelope["payload"]
        if signer != pinned or not isinstance(payload, dict):
            raise ValueError("signer mismatch")
        Ed25519PublicKey.from_public_bytes(pinned).verify(
            signature, DOMAIN + cbor2.dumps(payload, canonical=True)
        )
        return payload
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise RuntimeError("Router-CA directory signature verification failed") from exc


def verified_bundle(path: Path | None = None, allow_expired: bool = False):
    path = path or _cache_path()
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
        envelope = cache.get("bundle") if isinstance(cache, dict) else None
        if envelope is None:
            # Offline-import files may be the signed envelope itself.
            envelope = cache
        payload = _verify(envelope, _pinned_key())
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("no verified Router-CA directory bundle is available") from exc
    now = int(time.time())
    expires = payload.get("expires_at")
    grace = _stale_grace_seconds()
    if type(expires) is not int or (expires + max(0, grace) <= now and not allow_expired):
        raise RuntimeError("Router-CA directory bundle is expired")
    if expires > now + 600:
        raise RuntimeError("Router-CA directory bundle expiry exceeds policy")
    for record in payload.get("records", []):
        _verify(record, _pinned_key())
    return envelope, payload


def import_bundle(source: str | Path, destination: Path | None = None):
    source = Path(source)
    raw = json.loads(source.read_text(encoding="utf-8"))
    envelope = raw.get("bundle") if isinstance(raw, dict) and "bundle" in raw else raw
    payload = _verify(envelope, _pinned_key())
    now = int(time.time())
    if type(payload.get("expires_at")) is not int or payload["expires_at"] <= now or payload["expires_at"] > now + 600:
        raise RuntimeError("offline directory bundle is expired or has an invalid expiry")
    for record in payload.get("records", []):
        _verify(record, _pinned_key())
    target = destination or _cache_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    try:
        _, previous = verified_bundle(target, allow_expired=True)
    except RuntimeError:
        pass
    if previous and int(payload.get("directory_seq", -1)) < int(previous.get("directory_seq", -1)):
        raise RuntimeError("offline directory rollback rejected")
    old_lookups = {}
    try:
        cache = json.loads(target.read_text(encoding="utf-8"))
        if isinstance(cache, dict) and isinstance(cache.get("lookups"), dict):
            old_lookups = cache["lookups"]
    except (OSError, ValueError, TypeError):
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=".router-directory-", suffix=".tmp", dir=str(target.parent))
    try:
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"bundle": envelope, "lookups": old_lookups}, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, target)
        os.chmod(target, 0o640)
        try:
            import grp
            import pwd
            os.chown(target, pwd.getpwnam("nlsxnetos").pw_uid, grp.getgrnam("nlsxnetos").gr_gid)
        except (KeyError, PermissionError, OSError):
            pass
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return payload


def load():
    try:
        _, payload = verified_bundle()
    except RuntimeError:
        return []
    out = []
    seen_ids = set()
    seen_keys = {}
    for envelope in payload.get("records", []):
        record = _verify(envelope, _pinned_key())
        if type(record.get("valid_until")) is not int or record["valid_until"] <= int(time.time()):
            continue
        if record.get("status") != "ACTIVE":
            continue
        public_pem = record.get("ed25519_public_key")
        rsa_pem = record.get("rsa_encryption_public_key")
        endpoints = record.get("wan_endpoints") or []
        prefixes = record.get("prefixes") or []
        if not public_pem or not rsa_pem or not endpoints or not prefixes:
            continue
        try:
            ed_key = serialization.load_pem_public_key(public_pem.encode("ascii"))
            raw_key = ed_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            key_b64 = base64.b64encode(raw_key).decode("ascii")
            previous_router = seen_keys.get(key_b64)
            if previous_router is not None and previous_router != str(record["router_id"]):
                raise RuntimeError("duplicate active Router-CA public key")
            seen_keys[key_b64] = str(record["router_id"])
            for prefix in prefixes:
                entry_id = int.from_bytes(hashlib.sha256(
                    (str(record["router_id"]) + "|" + str(prefix)).encode("utf-8")
                ).digest()[:2], "big") or 1
                entry_id = ((entry_id - 1) % 65535) + 1
                if entry_id in seen_ids:
                    raise RuntimeError("Router-CA directory id collision")
                seen_ids.add(entry_id)
                entry = RouterCAEntry(
                    id=entry_id, prefix=str(prefix), label=str(record["router_id"]),
                    public_key=key_b64, endpoint=str(endpoints[0]),
                    encryption_public_key=base64.b64encode(
                        serialization.load_pem_public_key(rsa_pem.encode("ascii")).public_bytes(
                            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                        )
                    ).decode("ascii"),
                )
                entry.validate()
                out.append(entry)
        except (ValueError, TypeError, KeyError, UnicodeError):
            continue
    return sorted(out, key=lambda x: (x.label, x.prefix))


def save(entries):
    raise RuntimeError("unsigned Router-CA YAML is no longer a trust source; import a signed directory bundle")


def add(entry):
    raise RuntimeError("router directory is CA-managed; register changes on Router-CA and sync a signed bundle")


def remove(identifier):
    raise RuntimeError("router directory is CA-managed; revoke the router on Router-CA and sync a signed bundle")


def active_entries():
    return load()


def lookup(destination):
    import ipaddress
    address = ipaddress.ip_address(destination)
    matches = []
    for entry in active_entries():
        network = ipaddress.ip_network(entry.prefix, strict=False)
        if network.version == address.version and address in network:
            matches.append((network.prefixlen, entry))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]
