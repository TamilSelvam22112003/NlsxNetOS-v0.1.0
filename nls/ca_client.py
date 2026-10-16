"""Router-CA enrollment and persistent NLS control-channel client."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import tempfile
import threading
import time
import yaml
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import ipaddress
import cbor2

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .control_protocol import NLSControlError, client_handshake
from .identity import load_or_create
from .rsa import load_or_create as load_or_create_rsa


@dataclass(frozen=True)
class ClientSettings:
    endpoint: str
    server_id: str
    server_public_key: str
    router_id: str
    identity_key: Path
    certificate_file: Path
    ca_certificate_file: Path
    bootstrap_token_file: Path
    router_token_file: Path
    policy_file: Path
    revocation_file: Path
    connect_timeout_seconds: int = 10
    heartbeat_seconds: int = 30
    claimed_ipv6: str | None = None
    claimed_mac: str | None = None
    encryption_private_key: Path | None = None
    directory_file: Path | None = None
    stale_grace_seconds: int = 0
    trust_mode: str = "ca"
    rollback_mark_file: Path | None = None

    @classmethod
    def load(cls, path: str | Path):
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        cfg = raw.get("router_ca", raw)
        nls_config_path = Path(cfg.get("nls_config_file", "/etc/nlsxnetos/nls.yaml"))
        try:
            nls_raw = yaml.safe_load(nls_config_path.read_text(encoding="utf-8")) or {}
        except OSError:
            nls_raw = {}
        nls_cfg = nls_raw.get("nls", nls_raw)
        trust_mode = str(nls_cfg.get("trust_mode", cfg.get("trust_mode", "ca")))
        if trust_mode not in ("ca", "offline"):
            raise ValueError("trust_mode must be ca or offline")
        stale_grace = int(nls_cfg.get("stale_grace_seconds", cfg.get("stale_grace_seconds", 0)))
        endpoint_value = str(cfg["endpoint"]).strip()
        host, port = parse_endpoint(endpoint_value)
        if not 1 <= port <= 65535:
            raise ValueError("Router-CA port must be 1..65535")
        server_id = str(cfg.get("server_id", "nls-router-ca"))
        router_id = str(cfg["router_id"])
        if not server_id or len(server_id) > 128 or not router_id or len(router_id) > 128:
            raise ValueError("router_id and server_id must be 1..128 characters")
        server_key = str(cfg["server_public_key"])
        key_bytes = base64.b64decode(server_key.encode("ascii"), validate=True)
        if len(key_bytes) != 32:
            raise ValueError("server_public_key must be a base64 Ed25519 public key (32 bytes)")
        timeout = int(cfg.get("connect_timeout_seconds", 10))
        heartbeat = int(cfg.get("heartbeat_seconds", 30))
        if not 1 <= timeout <= 120 or not 5 <= heartbeat <= 3600:
            raise ValueError("invalid connection timeout or heartbeat interval")
        return cls(
            endpoint=endpoint_value,
            server_id=server_id,
            server_public_key=server_key,
            router_id=router_id,
            identity_key=Path(cfg.get("identity_key", "/var/lib/nlsxnetos/identity/ed25519.key")),
            certificate_file=Path(cfg.get("certificate_file", "/var/lib/nlsxnetos/identity/router.crt")),
            ca_certificate_file=Path(cfg.get("ca_certificate_file", "/etc/nlsxnetos/router-ca/ca-root.crt")),
            bootstrap_token_file=Path(cfg.get("bootstrap_token_file", "/etc/nlsxnetos/router-ca/bootstrap.token")),
            router_token_file=Path(cfg.get("router_token_file", "/etc/nlsxnetos/router-ca/router.token")),
            policy_file=Path(cfg.get("policy_file", "/var/lib/nlsxnetos/security/nls-policy.json")),
            revocation_file=Path(cfg.get("revocation_file", "/var/lib/nlsxnetos/security/nls-revocations.json")),
            connect_timeout_seconds=timeout,
            heartbeat_seconds=heartbeat,
            claimed_ipv6=str(cfg["claimed_ipv6"]) if cfg.get("claimed_ipv6") else None,
            claimed_mac=str(cfg["claimed_mac"]) if cfg.get("claimed_mac") else None,
            encryption_private_key=Path(cfg.get("encryption_private_key", "/var/lib/nlsxnetos/identity/rsa-encryption.pem")),
            directory_file=Path(cfg.get("directory_file", "/var/lib/nlsxnetos/security/router-directory.json")),
            stale_grace_seconds=stale_grace,
            trust_mode=trust_mode,
            rollback_mark_file=Path(cfg["rollback_mark_file"]) if cfg.get("rollback_mark_file") else None,
        )


def parse_endpoint(value: str):
    if value.startswith("["):
        if "]:" not in value:
            raise ValueError("IPv6 endpoint must use [address]:port syntax")
        host, port_text = value[1:].rsplit("]:", 1)
    else:
        if value.count(":") != 1:
            raise ValueError("IPv4 endpoint must use address:port syntax; bracket IPv6 endpoints")
        host, port_text = value.rsplit(":", 1)
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        port = int(port_text)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid Router-CA IP endpoint") from exc
    return host, port


def _read_secret(path: Path) -> str:
    try:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(f"secret file {path} must not grant group/other access (chmod 600)")
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"unable to read required enrollment credential file: {path}") from exc
    if len(value) < 32:
        raise RuntimeError(f"enrollment credential in {path} must contain at least 32 characters")
    return value


def _atomic_write(path: Path, data: bytes, mode: int = 0o640):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".nls-control-", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _load_root(path: Path):
    try:
        root = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"pre-provisioned Router-CA root certificate is unavailable/invalid: {path}") from exc
    if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise RuntimeError("configured Router-CA root certificate is not a CA")
    now = datetime.utcnow()
    if not root.not_valid_before <= now <= root.not_valid_after:
        raise RuntimeError("configured Router-CA root certificate is expired or not yet valid")
    key = root.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key.verify(root.signature, root.tbs_certificate_bytes, padding.PKCS1v15(), root.signature_hash_algorithm)
    else:
        raise RuntimeError("configured Router-CA root must use an RSA signing key in this version")
    return root


def _validate_leaf(cert_pem: str, root, settings: ClientSettings, identity_key):
    try:
        leaf = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("Router-CA returned an invalid certificate") from exc
    now = datetime.utcnow()
    if leaf.issuer != root.subject or not leaf.not_valid_before <= now <= leaf.not_valid_after:
        raise RuntimeError("Router-CA certificate issuer or validity check failed")
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cn) != 1 or cn[0].value != settings.router_id:
        raise RuntimeError("issued certificate router identity mismatch")
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise RuntimeError("router certificate is incorrectly marked as a CA")
    if ExtendedKeyUsageOID.CLIENT_AUTH not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
        raise RuntimeError("router certificate lacks client-authentication usage")
    if not isinstance(leaf.public_key(), ed25519.Ed25519PublicKey):
        raise RuntimeError("router certificate public key is not Ed25519")
    local_raw = identity_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    cert_raw = leaf.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if cert_raw != local_raw:
        raise RuntimeError("issued router certificate does not match the local private key")
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                             padding.PKCS1v15(), leaf.signature_hash_algorithm)
    return leaf


def _local_certificate(settings: ClientSettings, identity_key, root):
    if not settings.certificate_file.exists():
        return None
    pem = settings.certificate_file.read_text(encoding="ascii")
    _validate_leaf(pem, root, settings, identity_key)
    return pem


def _open_channel(settings: ClientSettings, identity_key, certificate_pem: str | None):
    host, port = parse_endpoint(settings.endpoint)
    sock = socket.create_connection((host, port), timeout=settings.connect_timeout_seconds)
    sock.settimeout(settings.connect_timeout_seconds)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        channel = client_handshake(
            sock, identity_key, settings.router_id, settings.server_public_key,
            settings.server_id, certificate_pem=certificate_pem,
        )
    except Exception:
        sock.close()
        raise
    return channel


def _persist_bundle(response: dict, settings: ClientSettings):
    policy = response.get("policy")
    revocations = response.get("revocations")
    if not isinstance(policy, dict) or not isinstance(revocations, dict):
        raise RuntimeError("Router-CA control response omitted policy/revocation state")
    if policy.get("control_protocol") != "NLS-Control-v1" or policy.get("record_cipher") != "AES-256-GCM":
        raise RuntimeError("Router-CA returned an unsupported NLS policy")
    envelope = response.get("directory_bundle")
    if not isinstance(envelope, dict):
        raise RuntimeError("Router-CA omitted its signed directory bundle")
    payload = _verify_directory_envelope(envelope, settings)
    now = int(time.time())
    if type(payload.get("expires_at")) is not int or payload["expires_at"] <= now or payload["expires_at"] > now + 600:
        raise RuntimeError("Router-CA directory bundle expiry invalid")
    for record_envelope in payload.get("records", []):
        _verify_directory_envelope(record_envelope, settings)
    try:
        cache, old_payload = _load_verified_cache_unchecked(settings)
    except RuntimeError:
        cache, old_payload = {"bundle": None, "lookups": {}}, None
    if old_payload and int(payload.get("directory_seq", -1)) < int(old_payload.get("directory_seq", -1)):
        raise RuntimeError("Router-CA directory rollback rejected")
    _save_verified_cache(
        settings, bundle=envelope, lookups=cache.get("lookups", {}), allow_mark_repair=True
    )
    _atomic_write(settings.policy_file, (json.dumps(policy, indent=2, sort_keys=True) + "\n").encode())
    _atomic_write(settings.revocation_file, (json.dumps(revocations, indent=2, sort_keys=True) + "\n").encode())



_DIRECTORY_DOMAIN = b"NLS-DIR-v1"
_VERIFIED_RECORD_CACHE = {}
_VERIFIED_RECORD_CACHE_LOCK = threading.RLock()


def _directory_path(settings: ClientSettings) -> Path:
    return getattr(settings, "directory_file", None) or (settings.identity_key.parent / "router-directory.json")


def _encryption_path(settings: ClientSettings) -> Path:
    return getattr(settings, "encryption_private_key", None) or (settings.identity_key.parent / "rsa-encryption.pem")


def _verify_directory_envelope(envelope: dict, settings: ClientSettings) -> dict:
    try:
        if envelope.get("encoding") != "canonical-cbor" or envelope.get("domain") != "NLS-DIR-v1":
            raise ValueError("unsupported signed directory format")
        pinned = base64.b64decode(settings.server_public_key.encode("ascii"), validate=True)
        signer = base64.b64decode(envelope["signer_public_key"].encode("ascii"), validate=True)
        signature = base64.b64decode(envelope["signature"].encode("ascii"), validate=True)
        payload = envelope["payload"]
        if signer != pinned or not isinstance(payload, dict):
            raise ValueError("directory signer/payload mismatch")
        ed25519.Ed25519PublicKey.from_public_bytes(pinned).verify(
            signature, _DIRECTORY_DOMAIN + cbor2.dumps(payload, canonical=True)
        )
        return payload
    except (KeyError, TypeError, ValueError, UnicodeError, InvalidSignature) as exc:
        raise RuntimeError("Router-CA directory signature verification failed") from exc


def _rollback_mark_path(settings: ClientSettings) -> Path:
    configured = getattr(settings, "rollback_mark_file", None)
    if configured:
        return Path(configured)
    environment = os.environ.get("NLSXNETOS_DIRECTORY_ROLLBACK_MARK")
    if environment:
        return Path(environment)
    cache_path = _directory_path(settings)
    if cache_path == Path("/var/lib/nlsxnetos/security/router-directory.json"):
        return Path("/var/lib/nlsxnetos/directory-rollback-mark.json")
    return cache_path.parent.parent / f"{cache_path.parent.name}-directory-rollback-mark.json"


def _read_rollback_mark(settings: ClientSettings):
    path = _rollback_mark_path(settings)
    try:
        mark = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "missing"
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None, "corrupt"
    if (
        not isinstance(mark, dict)
        or mark.get("version") != 1
        or type(mark.get("directory_seq")) is not int
        or not isinstance(mark.get("record_seq"), dict)
        or not isinstance(mark.get("cache_sha256"), str)
        or len(mark.get("cache_sha256", "")) != 64
        or type(mark.get("bundle_valid_until")) is not int
    ):
        return None, "corrupt"
    for router_id, sequence in mark["record_seq"].items():
        if not isinstance(router_id, str) or type(sequence) is not int or sequence < 0:
            return None, "corrupt"
    return mark, None


def _cache_record_sequences(cache: dict, settings: ClientSettings) -> dict:
    sequences = {}
    bundle = cache.get("bundle")
    if bundle:
        payload = _verify_directory_envelope(bundle, settings)
        for envelope in payload.get("records", []):
            record = _verify_directory_envelope(envelope, settings)
            router_id = record.get("router_id")
            if isinstance(router_id, str):
                sequences[router_id] = max(sequences.get(router_id, 0), int(record.get("record_seq", 0)))
    for envelope in cache.get("lookups", {}).values():
        record = _verify_directory_envelope(envelope, settings)
        router_id = record.get("router_id")
        if isinstance(router_id, str):
            sequences[router_id] = max(sequences.get(router_id, 0), int(record.get("record_seq", 0)))
    return sequences


def _chown_cache_owner(path: Path):
    try:
        import grp
        import pwd
        os.chown(path, pwd.getpwnam("nlsxnetos").pw_uid, grp.getgrnam("nlsxnetos").gr_gid)
    except (KeyError, PermissionError, OSError):
        # Development and CI environments may not have the installed service user.
        pass


def _load_verified_cache_unchecked(settings: ClientSettings):
    cache_path = _directory_path(settings)
    if not cache_path.exists():
        return {"bundle": None, "lookups": {}}, None
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        if not isinstance(cache, dict) or not isinstance(cache.get("lookups", {}), dict):
            raise ValueError("invalid cache")
        bundle = cache.get("bundle")
        bundle_payload = _verify_directory_envelope(bundle, settings) if bundle else None
        if bundle_payload:
            for envelope in bundle_payload.get("records", []):
                _verify_directory_envelope(envelope, settings)
        for envelope in cache.get("lookups", {}).values():
            _verify_directory_envelope(envelope, settings)
        return cache, bundle_payload
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"verified Router-CA directory cache is invalid ({type(exc).__name__})") from exc


def _validate_rollback_mark(settings: ClientSettings, cache: dict, payload: dict | None, raw_cache: bytes):
    mark, error = _read_rollback_mark(settings)
    if error:
        raise RuntimeError(f"Router-CA rollback mark {error}; fresh live sync required")
    if not secrets.compare_digest(mark["cache_sha256"], hashlib.sha256(raw_cache).hexdigest()):
        raise RuntimeError("Router-CA directory cache content hash mismatch; fresh live sync required")
    cache_directory_seq = int(payload.get("directory_seq", 0)) if payload else 0
    if mark["directory_seq"] != cache_directory_seq:
        raise RuntimeError("Router-CA rollback mark directory sequence does not match the cache")
    cache_sequences = _cache_record_sequences(cache, settings)
    for router_id, sequence in cache_sequences.items():
        if mark["record_seq"].get(router_id, -1) != sequence:
            raise RuntimeError("Router-CA rollback mark record sequence does not match the cache")
    bundle_expiry = int(payload.get("expires_at", 0)) if payload else 0
    if mark["bundle_valid_until"] != bundle_expiry:
        raise RuntimeError("Router-CA rollback mark bundle-expiry mismatch")


def _load_verified_cache(settings: ClientSettings):
    cache_path = _directory_path(settings)
    mark_path = _rollback_mark_path(settings)
    if not cache_path.exists():
        if mark_path.exists():
            raise RuntimeError("Router-CA directory cache is missing while its rollback mark exists")
        return {"bundle": None, "lookups": {}}, None
    cache, payload = _load_verified_cache_unchecked(settings)
    _validate_rollback_mark(settings, cache, payload, cache_path.read_bytes())
    return cache, payload


def _save_verified_cache(settings: ClientSettings, bundle=None, lookups=None, allow_mark_repair=False):
    cache_path = _directory_path(settings)
    try:
        previous, old_payload = _load_verified_cache_unchecked(settings)
    except RuntimeError:
        if not allow_mark_repair:
            raise
        previous, old_payload = {"bundle": None, "lookups": {}}, None
    if bundle is None:
        bundle = previous.get("bundle")
    if lookups is None:
        lookups = previous.get("lookups", {})
    new_payload = _verify_directory_envelope(bundle, settings) if bundle else None
    mark, mark_error = _read_rollback_mark(settings)
    if (mark_error or (cache_path.exists() and mark is not None and not secrets.compare_digest(
            mark["cache_sha256"], hashlib.sha256(cache_path.read_bytes()).hexdigest()
    ))) and not allow_mark_repair:
        raise RuntimeError("Router-CA rollback mark invalid; fresh live sync required")
    if allow_mark_repair and new_payload is None and (mark_error or old_payload is None):
        raise RuntimeError("a fresh signed Router-CA bundle is required to repair the rollback mark")

    new_records = {}
    if new_payload:
        now = int(time.time())
        if type(new_payload.get("expires_at")) is not int or new_payload["expires_at"] <= now or new_payload["expires_at"] > now + 600:
            raise RuntimeError("Router-CA directory bundle expiry invalid")
        for new_envelope in new_payload.get("records", []):
            new_record = _verify_directory_envelope(new_envelope, settings)
            if type(new_record.get("valid_until")) is not int or new_record["valid_until"] <= now:
                raise RuntimeError("Router-CA directory contains a stale record")
            new_records[new_record.get("router_id")] = int(new_record.get("record_seq", 0))
    new_directory_seq = int(new_payload.get("directory_seq", 0)) if new_payload else 0
    if mark and new_payload and new_directory_seq < mark["directory_seq"]:
        raise RuntimeError("Router-CA directory rollback rejected by rollback mark")
    if mark:
        for router_id, sequence in new_records.items():
            if sequence < mark["record_seq"].get(router_id, 0):
                raise RuntimeError("Router-CA record rollback rejected by rollback mark")
    if old_payload and new_payload and new_directory_seq < int(old_payload.get("directory_seq", -1)):
        raise RuntimeError("Router-CA directory rollback rejected")
    if old_payload and new_payload:
        old_records = {}
        for old_envelope in old_payload.get("records", []):
            old_record = _verify_directory_envelope(old_envelope, settings)
            old_records[old_record.get("router_id")] = int(old_record.get("record_seq", 0))
        for router_id, sequence in new_records.items():
            if router_id in old_records and sequence < old_records[router_id]:
                raise RuntimeError("Router-CA directory record rollback rejected")
    for router_id, envelope in lookups.items():
        record = _verify_directory_envelope(envelope, settings)
        old_envelope = previous.get("lookups", {}).get(router_id)
        if old_envelope:
            old_record = _verify_directory_envelope(old_envelope, settings)
            if int(record.get("record_seq", 0)) < int(old_record.get("record_seq", 0)):
                raise RuntimeError("Router-CA record rollback rejected")

    cache_object = {"bundle": bundle, "lookups": lookups}
    cache_bytes = (json.dumps(cache_object, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _atomic_write(cache_path, cache_bytes, 0o640)
    _chown_cache_owner(cache_path)
    high_water = dict(mark["record_seq"]) if mark else {}
    for router_id, sequence in _cache_record_sequences(cache_object, settings).items():
        high_water[router_id] = max(high_water.get(router_id, 0), sequence)
    directory_seq = max(mark["directory_seq"] if mark else 0, new_directory_seq)
    bundle_valid_until = int(new_payload.get("expires_at", 0)) if new_payload else (
        mark["bundle_valid_until"] if mark else 0
    )
    mark_object = {
        "version": 1,
        "directory_seq": directory_seq,
        "record_seq": high_water,
        "bundle_valid_until": bundle_valid_until,
        "cache_sha256": hashlib.sha256(cache_bytes).hexdigest(),
        "updated_at": int(time.time()),
    }
    mark_path = _rollback_mark_path(settings)
    _atomic_write(mark_path, (json.dumps(mark_object, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"), 0o600)
    _chown_cache_owner(mark_path)
    with _VERIFIED_RECORD_CACHE_LOCK:
        _VERIFIED_RECORD_CACHE.pop(str(cache_path), None)


def directory_freshness(settings: ClientSettings) -> int:
    cache, payload = _load_verified_cache(settings)
    if payload is None:
        return -1
    remaining = int(payload.get("expires_at", 0)) - int(time.time())
    if remaining + settings.stale_grace_seconds <= 0:
        return -1
    return max(0, remaining)


def is_revoked(serial: str, settings: ClientSettings) -> bool:
    cache, payload = _load_verified_cache(settings)
    if payload is None:
        raise RuntimeError("no verified Router-CA directory bundle")
    if directory_freshness(settings) < 0:
        raise RuntimeError("Router-CA directory freshness expired")
    normalized = str(serial).lower().removeprefix("0x")
    if normalized in {str(x).lower().removeprefix("0x") for x in payload.get("revoked_serials", [])}:
        return True
    for envelope in payload.get("records", []):
        record = _verify_directory_envelope(envelope, settings)
        if str(record.get("certificate_serial") or "").lower().removeprefix("0x") == normalized:
            if type(record.get("valid_until")) is not int or record["valid_until"] <= int(time.time()):
                return True
            return record.get("status") in ("REVOKED", "DISABLED", "EXPIRED")
    return False


def _enrollment_challenge(router_id: str, request_id: str, nonce: str, rsa_fingerprint: str) -> bytes:
    return (b"NLS-ENROLL-RSA-v1|" + router_id.encode("utf-8") + b"|" +
            request_id.encode("ascii") + b"|" + nonce.encode("ascii") + b"|" +
            rsa_fingerprint.encode("ascii"))


def _validate_lookup_response(response: dict, nonce: str, settings: ClientSettings) -> dict:
    if response.get("type") != "lookup-result" or response.get("client_nonce") != nonce:
        raise RuntimeError("Router-CA lookup response nonce/type mismatch")
    record = _verify_directory_envelope(response.get("record", {}), settings)
    if record.get("client_nonce") != nonce:
        raise RuntimeError("Router-CA lookup nonce is not bound to the signed record")
    now = int(time.time())
    valid_until = record.get("valid_until")
    if type(valid_until) is not int or valid_until <= now or valid_until > now + 30:
        raise RuntimeError("Router-CA lookup response freshness invalid")
    return record


def lookup(settings: ClientSettings, identity_key, target_router_id: str) -> dict:
    if settings.trust_mode == "offline":
        raise RuntimeError("offline trust mode disables live Router-CA lookup")
    if not target_router_id or len(target_router_id) > 128:
        raise ValueError("invalid target router id")
    root = _load_root(settings.ca_certificate_file)
    cert_pem = _local_certificate(settings, identity_key, root)
    if cert_pem is None:
        raise RuntimeError("router has no enrolled identity certificate")
    nonce = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    channel = _open_channel(settings, identity_key, cert_pem)
    try:
        channel.send({"type": "lookup", "router_id": settings.router_id,
                      "target_router_id": target_router_id, "client_nonce": nonce})
        response = channel.recv()
    finally:
        channel.close()
    record = _validate_lookup_response(response, nonce, settings)
    cache, payload = _load_verified_cache(settings)
    previous = cache.get("lookups", {}).get(target_router_id)
    if previous:
        old_record = _verify_directory_envelope(previous, settings)
        if int(record.get("record_seq", 0)) < int(old_record.get("record_seq", 0)):
            raise RuntimeError("Router-CA lookup record rollback rejected")
    if payload:
        for record_envelope in payload.get("records", []):
            cached_record = _verify_directory_envelope(record_envelope, settings)
            if cached_record.get("router_id") == target_router_id and int(record.get("record_seq", 0)) < int(cached_record.get("record_seq", 0)):
                raise RuntimeError("Router-CA lookup record rollback rejected")
    cache.setdefault("lookups", {})[target_router_id] = response["record"]
    _save_verified_cache(settings, bundle=cache.get("bundle"), lookups=cache["lookups"])
    return record


def directory_sync(settings: ClientSettings, identity_key, since_seq: int | None = None) -> dict:
    if settings.trust_mode == "offline":
        raise RuntimeError("offline trust mode disables live directory synchronization")
    try:
        cache, payload = _load_verified_cache(settings)
    except RuntimeError:
        try:
            cache, payload = _load_verified_cache_unchecked(settings)
        except RuntimeError:
            cache, payload = {"bundle": None, "lookups": {}}, None
    if since_seq is None:
        since_seq = int(payload.get("directory_seq", 0)) if payload else 0
    root = _load_root(settings.ca_certificate_file)
    cert_pem = _local_certificate(settings, identity_key, root)
    if cert_pem is None:
        raise RuntimeError("router has no enrolled identity certificate")
    channel = _open_channel(settings, identity_key, cert_pem)
    try:
        channel.send({"type": "directory-sync", "router_id": settings.router_id, "since_seq": since_seq})
        response = channel.recv()
    finally:
        channel.close()
    if response.get("type") != "directory-sync-result" or not response.get("ok"):
        raise RuntimeError("Router-CA directory synchronization failed")
    envelope = response.get("directory_bundle")
    bundle = _verify_directory_envelope(envelope, settings)
    now = int(time.time())
    if type(bundle.get("expires_at")) is not int or bundle["expires_at"] <= now or bundle["expires_at"] > now + 600:
        raise RuntimeError("Router-CA directory bundle expiry invalid")
    if int(bundle.get("directory_seq", -1)) < int(since_seq):
        raise RuntimeError("Router-CA directory sequence rollback rejected")
    for record_envelope in bundle.get("records", []):
        record = _verify_directory_envelope(record_envelope, settings)
        if type(record.get("valid_until")) is not int or record["valid_until"] <= now:
            raise RuntimeError("Router-CA directory contains a stale record")
    _save_verified_cache(settings, bundle=envelope, lookups=cache.get("lookups", {}), allow_mark_repair=True)
    return bundle


def enroll(settings: ClientSettings, identity_key):
    root = _load_root(settings.ca_certificate_file)
    bootstrap_token = _read_secret(settings.bootstrap_token_file)
    router_token = _read_secret(settings.router_token_file)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, settings.router_id)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(settings.router_id)]), critical=False)
        .sign(identity_key, algorithm=None)
    )
    request_id = secrets.token_hex(24)
    nonce = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
    rsa_key = load_or_create_rsa(_encryption_path(settings))
    if not isinstance(rsa_key, rsa.RSAPrivateKey) or rsa_key.key_size != 3072:
        raise RuntimeError("router RSA encryption key must be RSA-3072")
    rsa_public_pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    rsa_public_der = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    rsa_fingerprint = hashlib.sha256(rsa_public_der).hexdigest()
    challenge = _enrollment_challenge(settings.router_id, request_id, nonce, rsa_fingerprint)
    rsa_proof = rsa_key.sign(
        challenge,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    request = {
        "protocol_version": 1,
        "router_id": settings.router_id,
        "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "request_id": request_id,
        "nonce": nonce,
        "timestamp": int(time.time()),
        "rsa_encryption_public_key": rsa_public_pem,
        "rsa_proof_of_possession": base64.b64encode(rsa_proof).decode("ascii"),
        "claimed_ipv6": settings.claimed_ipv6,
        "claimed_mac": settings.claimed_mac,
    }
    channel = _open_channel(settings, identity_key, None)
    try:
        channel.send({"type": "enroll", "request": request,
                      "bootstrap_token": bootstrap_token, "router_token": router_token})
        response = channel.recv()
    finally:
        channel.close()
    if response.get("type") != "enrollment-result" or not response.get("ok"):
        raise RuntimeError(response.get("message", "Router-CA enrollment was denied"))
    returned_root = x509.load_pem_x509_certificate(response["ca_certificate_pem"].encode("ascii"))
    local_fp = hashlib.sha256(root.public_bytes(serialization.Encoding.DER)).digest()
    returned_fp = hashlib.sha256(returned_root.public_bytes(serialization.Encoding.DER)).digest()
    if local_fp != returned_fp:
        raise RuntimeError("Router-CA response root does not match the pre-provisioned trust anchor")
    leaf = _validate_leaf(response["certificate_pem"], root, settings, identity_key)
    if response.get("serial_number") != format(leaf.serial_number, "x"):
        raise RuntimeError("Router-CA certificate serial does not match response metadata")
    _atomic_write(settings.certificate_file, response["certificate_pem"].encode("ascii"), 0o640)
    _persist_bundle(response, settings)
    print(f"NLS Router-CA enrollment successful: router={settings.router_id} serial={response['serial_number']}")
    print(f"Identity certificate installed at {settings.certificate_file}")
    return response


def refresh_live_state(settings: ClientSettings, identity_key):
    """Fetch and persist an authenticated CA heartbeat before trusting cached state."""
    root = _load_root(settings.ca_certificate_file)
    cert_pem = _local_certificate(settings, identity_key, root)
    if cert_pem is None:
        raise RuntimeError("router has no enrolled identity certificate")
    channel = _open_channel(settings, identity_key, cert_pem)
    try:
        channel.send({
            "type": "heartbeat",
            "router_id": settings.router_id,
            "timestamp": int(time.time()),
        })
        response = channel.recv()
        if response.get("type") != "heartbeat-result" or not response.get("ok"):
            raise RuntimeError(response.get("message", "Router-CA heartbeat rejected"))
        _persist_bundle(response, settings)
        return response
    finally:
        channel.close()


def _send_command(settings, identity_key, action, keep_open=False):
    root = _load_root(settings.ca_certificate_file)
    cert_pem = _local_certificate(settings, identity_key, root)
    if cert_pem is None:
        raise RuntimeError("router has no enrolled identity certificate; run router-ca-client enroll")
    channel = _open_channel(settings, identity_key, cert_pem)
    try:
        channel.send({"type": action, "router_id": settings.router_id})
        response = channel.recv()
        if response.get("type") == "error" or not response.get("ok"):
            raise RuntimeError(response.get("message", "Router-CA rejected request"))
        if action in ("sync", "heartbeat", "status"):
            _persist_bundle(response, settings)
        print(json.dumps({k: v for k, v in response.items() if k not in ("certificate_pem", "ca_certificate_pem")}, indent=2))
        return channel, response
    except Exception:
        channel.close()
        raise


def run_agent(settings: ClientSettings):
    identity_key = load_or_create(settings.identity_key)
    if not settings.certificate_file.exists():
        enroll(settings, identity_key)
        # Reconnect so subsequent control-plane traffic is certificate-authenticated.
    while True:
        channel = None
        try:
            root = _load_root(settings.ca_certificate_file)
            cert_pem = _local_certificate(settings, identity_key, root)
            if cert_pem is None:
                enroll(settings, identity_key)
                continue
            channel = _open_channel(settings, identity_key, cert_pem)
            channel.send({"type": "sync", "router_id": settings.router_id})
            response = channel.recv()
            if response.get("type") == "error" or not response.get("ok"):
                raise RuntimeError(response.get("message", "NLS policy synchronization failed"))
            _persist_bundle(response, settings)
            print(f"NLS mNLS control channel ready for {settings.router_id}; policy synchronized")
            while True:
                time.sleep(settings.heartbeat_seconds)
                channel.send({"type": "heartbeat", "router_id": settings.router_id, "timestamp": int(time.time())})
                response = channel.recv()
                if response.get("type") != "heartbeat-result" or not response.get("ok"):
                    raise RuntimeError("Router-CA heartbeat rejected")
                _persist_bundle(response, settings)
        except KeyboardInterrupt:
            if channel:
                try:
                    channel.send({"type": "close"})
                    channel.recv()
                except Exception:
                    pass
                channel.close()
            return
        except Exception as exc:
            print(f"NLS control channel unavailable: {exc}; retrying in 5 seconds")
            if channel:
                channel.close()
            time.sleep(5)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nlsxnetos router-ca-client")
    parser.add_argument("action", choices=("enroll", "sync", "status", "run", "import-bundle"))
    parser.add_argument("--config", default="/etc/nlsxnetos/router-ca-client.yaml")
    parser.add_argument("--bundle-file")
    parser.add_argument("--confirm-rollback-reset", action="store_true")
    args = parser.parse_args(argv)
    settings = ClientSettings.load(args.config)
    identity_key = load_or_create(settings.identity_key)
    if args.action == "enroll":
        enroll(settings, identity_key)
    elif args.action == "run":
        run_agent(settings)
    elif args.action == "import-bundle":
        if settings.trust_mode != "offline":
            raise RuntimeError("import-bundle is only available in offline trust mode")
        if not args.bundle_file:
            raise RuntimeError("import-bundle requires --bundle-file")
        if not args.confirm_rollback_reset:
            raise RuntimeError("offline bundle import requires --confirm-rollback-reset")
        envelope = json.loads(Path(args.bundle_file).read_text(encoding="utf-8"))
        payload = _verify_directory_envelope(envelope, settings)
        now = int(time.time())
        if type(payload.get("expires_at")) is not int or payload["expires_at"] <= now or payload["expires_at"] > now + 600:
            raise RuntimeError("offline directory bundle expiry invalid")
        for record_envelope in payload.get("records", []):
            record = _verify_directory_envelope(record_envelope, settings)
            if type(record.get("valid_until")) is not int or record["valid_until"] <= now:
                raise RuntimeError("offline directory contains a stale record")
        _save_verified_cache(settings, bundle=envelope, lookups={}, allow_mark_repair=True)
        print("NLS_OFFLINE_DIRECTORY_IMPORTED directory_seq=" + str(payload.get("directory_seq", 0)) +
              " freshness=degraded")
    else:
        channel, _ = _send_command(settings, identity_key, args.action)
        channel.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def cached_record(router_id: str, settings: ClientSettings) -> dict:
    """Return a verified RDR from a short-lived receive-path cache.

    The file and rollback-mark hashes are checked on every access; signatures and
    CBOR parsing are repeated at least every min(heartbeat, 5 seconds). A changed
    cache, revocation file, directory sequence, record sequence, or expiry forces
    a cold verification path.
    """
    cache_path = _directory_path(settings)
    try:
        raw_cache = cache_path.read_bytes()
    except OSError as exc:
        raise RuntimeError("verified Router-CA directory cache is unavailable") from exc
    mark, mark_error = _read_rollback_mark(settings)
    if mark_error:
        raise RuntimeError(f"Router-CA rollback mark {mark_error}; fresh live sync required")
    if not secrets.compare_digest(mark["cache_sha256"], hashlib.sha256(raw_cache).hexdigest()):
        raise RuntimeError("Router-CA directory cache content hash mismatch; fresh live sync required")
    revocation_path = settings.revocation_file
    policy_path = settings.policy_file
    try:
        revocation_bytes = revocation_path.read_bytes()
    except OSError:
        revocation_bytes = b""
    try:
        policy_bytes = policy_path.read_bytes()
    except OSError:
        policy_bytes = b""
    source_hash = hashlib.sha256(raw_cache + b"\\0" + revocation_bytes + b"\\0" + policy_bytes).hexdigest()
    now_wall = int(time.time())
    now_mono = time.monotonic()
    key = str(cache_path)
    with _VERIFIED_RECORD_CACHE_LOCK:
        entry = _VERIFIED_RECORD_CACHE.get(key)
        if entry and entry["source_hash"] == source_hash and now_mono < entry["next_check_mono"]:
            if mark["directory_seq"] != entry["directory_seq"]:
                raise RuntimeError("Router-CA rollback mark directory sequence does not match the cache")
            for cached_router, sequence in entry["record_seq"].items():
                if mark["record_seq"].get(cached_router, -1) != sequence:
                    raise RuntimeError("Router-CA rollback mark record sequence does not match the cache")
            if mark["bundle_valid_until"] != entry["bundle_expires_at"]:
                raise RuntimeError("Router-CA rollback mark bundle-expiry mismatch")
            if entry["bundle_expires_at"] <= now_wall:
                raise RuntimeError("cached Router-CA directory freshness expired")
            record = entry["records"].get(router_id)
            if record is None:
                raise RuntimeError("no signed cached Router-CA record")
            if type(record.get("valid_until")) is not int or record["valid_until"] <= now_wall:
                raise RuntimeError("cached Router-CA record is stale")
            if record.get("status") != "ACTIVE":
                raise RuntimeError("cached Router-CA record is not active")
            serial = str(record.get("certificate_serial") or "").lower().removeprefix("0x")
            if serial in entry["revoked_serials"]:
                raise RuntimeError("cached Router-CA record is revoked")
            return dict(record)

    cache, bundle = _load_verified_cache(settings)
    if bundle is None:
        raise RuntimeError("no verified Router-CA directory bundle")
    now = int(time.time())
    if type(bundle.get("expires_at")) is not int or bundle["expires_at"] <= now:
        raise RuntimeError("cached Router-CA directory freshness expired")
    records = {}
    for envelope in cache.get("lookups", {}).values():
        record = _verify_directory_envelope(envelope, settings)
        current = records.get(record.get("router_id"))
        if current is None or int(record.get("record_seq", 0)) > int(current.get("record_seq", 0)):
            records[record.get("router_id")] = record
    for envelope in bundle.get("records", []):
        record = _verify_directory_envelope(envelope, settings)
        current = records.get(record.get("router_id"))
        if current is None or int(record.get("record_seq", 0)) > int(current.get("record_seq", 0)):
            records[record.get("router_id")] = record
    record_sequences = {rid: int(item.get("record_seq", 0)) for rid, item in records.items()}
    revoked_serials = {
        str(serial).lower().removeprefix("0x") for serial in bundle.get("revoked_serials", [])
    }
    entry = {
        "source_hash": source_hash,
        "records": records,
        "record_seq": record_sequences,
        "directory_seq": int(bundle.get("directory_seq", 0)),
        "bundle_expires_at": int(bundle.get("expires_at", 0)),
        "revoked_serials": revoked_serials,
        "next_check_mono": now_mono + min(max(1, int(settings.heartbeat_seconds)), 5),
    }
    with _VERIFIED_RECORD_CACHE_LOCK:
        _VERIFIED_RECORD_CACHE[key] = entry
    record = records.get(router_id)
    if record is None:
        raise RuntimeError("no signed cached Router-CA record")
    if type(record.get("valid_until")) is not int or record["valid_until"] <= now:
        raise RuntimeError("cached Router-CA record is stale")
    if record.get("status") != "ACTIVE":
        raise RuntimeError("cached Router-CA record is not active")
    serial = str(record.get("certificate_serial") or "").lower().removeprefix("0x")
    if serial in revoked_serials:
        raise RuntimeError("cached Router-CA record is revoked")
    return dict(record)



def lookup_envelope(router_id: str, settings: ClientSettings) -> dict:
    """Return the exact signed envelope saved by a successful live lookup."""
    cache, _ = _load_verified_cache(settings)
    envelope = cache.get("lookups", {}).get(router_id)
    if not isinstance(envelope, dict):
        raise RuntimeError("no signed Router-CA lookup envelope")
    record = _verify_directory_envelope(envelope, settings)
    if record.get("router_id") != router_id:
        raise RuntimeError("signed Router-CA lookup identity mismatch")
    if type(record.get("valid_until")) is not int or record["valid_until"] <= int(time.time()):
        raise RuntimeError("signed Router-CA lookup expired")
    return envelope
