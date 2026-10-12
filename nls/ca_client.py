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
import time
import yaml
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .control_protocol import NLSControlError, client_handshake
from .identity import load_or_create


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

    @classmethod
    def load(cls, path: str | Path):
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        cfg = raw.get("router_ca", raw)
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
    _atomic_write(settings.policy_file, (json.dumps(policy, indent=2, sort_keys=True) + "\n").encode())
    _atomic_write(settings.revocation_file, (json.dumps(revocations, indent=2, sort_keys=True) + "\n").encode())


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
    request = {
        "protocol_version": 1,
        "router_id": settings.router_id,
        "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "request_id": secrets.token_hex(24),
        "nonce": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("="),
        "timestamp": int(time.time()),
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
    parser.add_argument("action", choices=("enroll", "sync", "status", "run"))
    parser.add_argument("--config", default="/etc/nlsxnetos/router-ca-client.yaml")
    args = parser.parse_args(argv)
    settings = ClientSettings.load(args.config)
    identity_key = load_or_create(settings.identity_key)
    if args.action == "enroll":
        enroll(settings, identity_key)
    elif args.action == "run":
        run_agent(settings)
    else:
        channel, _ = _send_command(settings, identity_key, args.action)
        channel.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
