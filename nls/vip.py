"""Temporary vIP allocation, assignment, persistence, and crash cleanup."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import subprocess
import time
from pathlib import Path


DEFAULT_POOL = os.environ.get("NLSXNETOS_VIP_POOL", "fd42:4e4c:53::/64")
DEFAULT_STATE = Path(os.environ.get("NLSXNETOS_VIP_STATE", "/run/nlsxnetos/vip-state.json"))
VIP_TTL_SECONDS = 10


def derive_vip_candidate(
    source_record: dict,
    destination_record: dict,
    vip_nonce: bytes,
    time_bucket: int,
    policy_version: int = 1,
) -> ipaddress.IPv6Address:
    """Derive the normative NLH2 bootstrap vIP candidate from signed RDR fields."""
    from .source_token import validate_original_ip

    if not isinstance(source_record, dict) or not isinstance(destination_record, dict):
        raise ValueError("vIP derivation requires source and destination RDR mappings")
    if not isinstance(vip_nonce, bytes) or len(vip_nonce) != 32:
        raise ValueError("vip_nonce must be exactly 32 bytes")
    if type(time_bucket) is not int or not 0 <= time_bucket < (1 << 64):
        raise ValueError("time_bucket must be an unsigned 64-bit integer")
    if type(policy_version) is not int or policy_version != 1:
        raise ValueError("unsupported vIP address policy version")

    def record_fields(record: dict, label: str) -> tuple[bytes, bytes, bytes]:
        original_ip = validate_original_ip(record.get("originalIP")).packed
        try:
            certificate_der = base64.b64decode(record["certificate_der_b64"], validate=True)
            public_key_spki_der = base64.b64decode(
                record["ed25519_public_key_spki_der_b64"], validate=True
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{label} RDR certificate/public key encoding is invalid") from exc
        if not certificate_der or not public_key_spki_der:
            raise ValueError(f"{label} RDR certificate/public key encoding is empty")
        return original_ip, certificate_der, public_key_spki_der

    # Normative ordering: destination router D fields precede source router S fields.
    d_ip, d_certificate, d_spki = record_fields(destination_record, "destination")
    s_ip, s_certificate, s_spki = record_fields(source_record, "source")
    fields = (
        b"NLS-vIP-v1",
        d_ip,
        d_certificate,
        d_spki,
        s_ip,
        s_certificate,
        s_spki,
        vip_nonce,
        time_bucket.to_bytes(8, "big"),
    )
    encoded = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return ipaddress.IPv6Address(hashlib.sha512(encoded).digest()[:16])


def _run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


class VIPManager:
    def __init__(self, interface: str, pool: str = DEFAULT_POOL,
                 state_path: str | Path = DEFAULT_STATE, ttl: int = VIP_TTL_SECONDS):
        if not interface or len(interface) > 15 or "/" in interface or "\x00" in interface:
            raise ValueError("invalid vIP interface")
        network = ipaddress.ip_network(pool, strict=True)
        if network.version != 6 or network.prefixlen > 120 or not network.is_private:
            raise ValueError("vIP pool must be a private IPv6 network with prefix <= /120")
        if not 1 <= int(ttl) <= VIP_TTL_SECONDS:
            raise ValueError("vIP TTL must be between 1 and 10 seconds")
        self.interface = interface
        self.pool = network
        self.state_path = Path(state_path)
        self.ttl = int(ttl)
        self.active: dict[str, float] = {}
        self.derived_addresses: set[str] = set()
        self.last_assigned: str | None = None
        self.last_assigned_verified = False
        self.last_released: str | None = None

    def _persist(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        payload = {"version": 2, "interface": self.interface,
                   "addresses": sorted(self.active), "derived_addresses": sorted(self.derived_addresses),
                   "pool": str(self.pool), "written_at": int(time.time()),
                   "last_assigned": self.last_assigned, "last_assigned_verified": self.last_assigned_verified,
                   "last_released": self.last_released}
        tmp = self.state_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.state_path)
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    def cleanup_startup(self):
        """Remove addresses left by a crash, using only our own validated state file."""
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if data.get("version") not in (1, 2) or data.get("interface") != self.interface:
                raise ValueError("vIP recovery state mismatch")
            addresses = data.get("addresses", [])
            if not isinstance(addresses, list) or len(addresses) > 4096:
                raise ValueError("invalid vIP recovery state")
            recovery_pool = ipaddress.ip_network(data.get("pool", str(self.pool)), strict=True)
            if recovery_pool.version != 6 or not recovery_pool.is_private:
                raise ValueError("invalid vIP recovery pool")
            derived_raw = data.get("derived_addresses", []) if data.get("version") == 2 else []
            if not isinstance(derived_raw, list) or len(derived_raw) > len(addresses):
                raise ValueError("invalid derived vIP recovery state")
            derived = {str(ipaddress.IPv6Address(raw)) for raw in derived_raw}
            normalized_addresses = {str(ipaddress.IPv6Address(raw)) for raw in addresses}
            if not derived.issubset(normalized_addresses):
                raise ValueError("derived vIP recovery state is inconsistent")
            from .source_token import address_policy_valid
            remaining = []
            for raw in addresses:
                address = ipaddress.ip_address(raw)
                if address.version != 6:
                    continue
                normalized = str(address)
                if normalized in derived:
                    if not address_policy_valid(address, 1):
                        raise ValueError("derived vIP recovery address violates policy")
                elif address not in recovery_pool:
                    continue
                result = subprocess.run(
                    ["ip", "-6", "addr", "del", f"{address}/128", "dev", self.interface],
                    check=False, capture_output=True, text=True,
                )
                if result.returncode != 0:
                    try:
                        shown = subprocess.run(
                            ["ip", "-6", "addr", "show", "dev", self.interface],
                            check=True, capture_output=True, text=True,
                        ).stdout
                    except (OSError, subprocess.CalledProcessError):
                        remaining.append(str(address))
                        continue
                    if str(address) in shown:
                        remaining.append(str(address))
            if remaining:
                # Keep the recovery file intact and fail closed; do not lose
                # ownership of addresses that the kernel still has assigned.
                raise RuntimeError("unable to remove stale vIP addresses: " + ",".join(remaining))
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            # Never erase the only recovery record if its contents cannot be trusted.
            raise RuntimeError("invalid or unreadable vIP recovery state") from exc
        self.active.clear()
        self.derived_addresses.clear()
        try:
            self.state_path.unlink()
        except FileNotFoundError:
            pass

    def allocate(self) -> str:
        """Allocate a fresh random /128, assign it with nodad, and persist it."""
        for _ in range(128):
            host_bits = 128 - self.pool.prefixlen
            suffix = secrets.randbits(host_bits)
            address = ipaddress.IPv6Address(int(self.pool.network_address) | suffix)
            if address == self.pool.network_address or address in self.active:
                continue
            if address.is_multicast or address.is_link_local or address.is_unspecified:
                continue
            text = str(address)
            try:
                _run(["ip", "-6", "addr", "add", f"{text}/128", "dev",
                      self.interface, "nodad"])
            except subprocess.CalledProcessError:
                continue
            try:
                observed = subprocess.run(
                    ["ip", "-6", "addr", "show", "dev", self.interface],
                    check=True, capture_output=True, text=True,
                ).stdout
                if text not in observed:
                    raise RuntimeError("assigned vIP is not visible in kernel address state")
            except Exception as exc:
                subprocess.run(
                    ["ip", "-6", "addr", "del", f"{text}/128", "dev", self.interface],
                    check=False, capture_output=True, text=True,
                )
                raise RuntimeError("unable to verify vIP assignment") from exc
            self.active[text] = time.monotonic() + self.ttl
            self.last_assigned = text
            self.last_assigned_verified = True
            try:
                self._persist()
                return text
            except Exception as exc:
                # Persistence failure must not strand an address that allocate()
                # never returned to its caller. Attempt immediate kernel cleanup.
                removed = subprocess.run(
                    ["ip", "-6", "addr", "del", f"{text}/128", "dev", self.interface],
                    check=False, capture_output=True, text=True,
                )
                if removed.returncode == 0:
                    self.active.pop(text, None)
                    self.last_released = text
                    try:
                        self._persist()
                    except OSError:
                        pass
                raise RuntimeError("unable to persist vIP ownership state") from exc
        raise RuntimeError("unable to allocate an unused temporary vIP")

    def assign_derived(self, address: str) -> str:
        """Assign and persist a policy-valid digest-derived vIP /128."""
        from .source_token import address_policy_valid

        normalized = str(ipaddress.IPv6Address(address))
        if not address_policy_valid(normalized, 1):
            raise ValueError("derived vIP candidate violates address policy v1")
        if normalized in self.active:
            raise RuntimeError("derived vIP candidate is already active")
        try:
            _run(["ip", "-6", "addr", "add", f"{normalized}/128", "dev",
                  self.interface, "nodad"])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("unable to assign derived vIP candidate") from exc
        try:
            observed = subprocess.run(
                ["ip", "-6", "addr", "show", "dev", self.interface],
                check=True, capture_output=True, text=True,
            ).stdout
            if normalized not in observed:
                raise RuntimeError("assigned derived vIP is not visible in kernel address state")
        except Exception as exc:
            subprocess.run(
                ["ip", "-6", "addr", "del", f"{normalized}/128", "dev", self.interface],
                check=False, capture_output=True, text=True,
            )
            raise RuntimeError("unable to verify derived vIP assignment") from exc
        self.active[normalized] = time.monotonic() + self.ttl
        self.derived_addresses.add(normalized)
        self.last_assigned = normalized
        self.last_assigned_verified = True
        try:
            self._persist()
            return normalized
        except Exception as exc:
            removed = subprocess.run(
                ["ip", "-6", "addr", "del", f"{normalized}/128", "dev", self.interface],
                check=False, capture_output=True, text=True,
            )
            if removed.returncode == 0:
                self.active.pop(normalized, None)
                self.derived_addresses.discard(normalized)
                self.last_released = normalized
                try:
                    self._persist()
                except OSError:
                    pass
            raise RuntimeError("unable to persist derived vIP ownership state") from exc

    def expired(self, address: str, now: float | None = None) -> bool:
        deadline = self.active.get(str(ipaddress.IPv6Address(address)))
        return deadline is None or deadline <= (time.monotonic() if now is None else now)

    def release(self, address: str) -> None:
        try:
            normalized = str(ipaddress.IPv6Address(address))
        except ValueError:
            return
        if normalized not in self.active:
            return
        result = subprocess.run(
            ["ip", "-6", "addr", "del", f"{normalized}/128", "dev", self.interface],
            check=False, capture_output=True, text=True,
        )
        if result.returncode != 0:
            # "Address not found" is fine only if the kernel confirms absence.
            try:
                shown = subprocess.run(
                    ["ip", "-6", "addr", "show", "dev", self.interface],
                    check=True, capture_output=True, text=True,
                ).stdout
            except (OSError, subprocess.CalledProcessError) as exc:
                self._persist()
                raise RuntimeError("unable to verify vIP removal") from exc
            if normalized in shown:
                self._persist()
                raise RuntimeError("kernel still has the temporary vIP assigned")
        self.active.pop(normalized, None)
        self.derived_addresses.discard(normalized)
        self.last_released = normalized
        self._persist()

    def expire(self, now: float | None = None) -> list[str]:
        current = time.monotonic() if now is None else now
        expired = [address for address, deadline in self.active.items() if deadline <= current]
        removed = []
        for address in expired:
            try:
                self.release(address)
                removed.append(address)
            except (OSError, RuntimeError, subprocess.CalledProcessError):
                # Keep failed removals in the state file for shutdown/startup retry.
                continue
        return removed

    def release_all(self) -> None:
        for address in list(self.active):
            try:
                self.release(address)
            except (OSError, RuntimeError, subprocess.CalledProcessError):
                # Continue attempting remaining addresses; recovery state stays persisted.
                continue

    def bind_socket(self, address: str, port: int):
        """Create an IPv6 UDP socket bound to the temporary address."""
        import socket
        normalized = str(ipaddress.IPv6Address(address))
        if normalized not in self.active or self.expired(normalized):
            raise RuntimeError("vIP is not active")
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "IPV6_RECVPKTINFO"):
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        try:
            sock.bind((normalized, int(port)))
        except Exception:
            sock.close()
            self.release(normalized)
            raise
        return sock
