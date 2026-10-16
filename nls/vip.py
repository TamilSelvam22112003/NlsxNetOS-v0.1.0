"""Temporary vIP allocation, assignment, persistence, and crash cleanup."""
from __future__ import annotations

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
        self.last_assigned: str | None = None
        self.last_released: str | None = None

    def _persist(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        payload = {"version": 1, "interface": self.interface,
                   "addresses": sorted(self.active), "written_at": int(time.time()),
                   "last_assigned": self.last_assigned, "last_released": self.last_released}
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
            if data.get("version") != 1 or data.get("interface") != self.interface:
                raise ValueError("vIP recovery state mismatch")
            addresses = data.get("addresses", [])
            if not isinstance(addresses, list) or len(addresses) > 4096:
                raise ValueError("invalid vIP recovery state")
            remaining = []
            for raw in addresses:
                address = ipaddress.ip_address(raw)
                if address.version != 6 or address not in self.pool:
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
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            # Do not act on malformed recovery state.
            pass
        self.active.clear()
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
            self.active[text] = time.monotonic() + self.ttl
            self.last_assigned = text
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
        try:
            sock.bind((normalized, int(port)))
        except Exception:
            sock.close()
            self.release(normalized)
            raise
        return sock
