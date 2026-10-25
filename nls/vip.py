"""Temporary vIP allocation, assignment, persistence, and crash cleanup."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
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
        self.address_modes: dict[str, str] = {}
        self.last_assigned: str | None = None
        self.last_assigned_verified = False
        self.last_released: str | None = None

    def _persist(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        payload = {"version": 1, "interface": self.interface,
                   "addresses": sorted(self.active), "pool": str(self.pool), "written_at": int(time.time()),
                   "last_assigned": self.last_assigned, "last_assigned_verified": self.last_assigned_verified,
                   "last_released": self.last_released,
                   "address_modes": {address: self.address_modes.get(address, "pool")
                                     for address in sorted(self.active)}}
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
            recovery_pool = ipaddress.ip_network(data.get("pool", str(self.pool)), strict=True)
            if recovery_pool.version != 6 or not recovery_pool.is_private:
                raise ValueError("invalid vIP recovery pool")
            address_modes = data.get("address_modes", {})
            if not isinstance(address_modes, dict):
                raise ValueError("invalid vIP recovery address modes")
            from .vip_policy import validate_vip_candidate
            remaining = []
            for raw in addresses:
                address = ipaddress.ip_address(raw)
                if address.version != 6:
                    raise ValueError("invalid address in vIP recovery state")
                mode = address_modes.get(str(address), "pool")
                if mode == "pool":
                    if address not in recovery_pool:
                        raise ValueError("pool address outside recovery pool")
                elif mode == "derived":
                    validate_vip_candidate(address, 1)
                else:
                    raise ValueError("unknown vIP recovery address mode")
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
        self.address_modes.clear()
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
            self.address_modes[text] = "pool"
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

    def expired(self, address: str, now: float | None = None) -> bool:
        deadline = self.active.get(str(ipaddress.IPv6Address(address)))
        return deadline is None or deadline <= (time.monotonic() if now is None else now)

    def allocate_specific(self, address: str) -> str:
        """Assign a policy-v1 derived vIP for one short-lived handshake.

        This assigns the address locally; it does not guarantee WAN reachability
        or bypass upstream source-address validation.
        """
        from .vip_policy import validate_vip_candidate

        normalized = str(validate_vip_candidate(address, 1))
        if normalized in self.active:
            raise RuntimeError("derived vIP is already active")
        _run(["ip", "-6", "addr", "add", f"{normalized}/128", "dev",
              self.interface, "nodad"])
        try:
            shown = subprocess.run(
                ["ip", "-6", "addr", "show", "dev", self.interface],
                check=True, capture_output=True, text=True,
            ).stdout
            if normalized not in shown:
                raise RuntimeError("derived vIP assignment is not visible in kernel state")
            self.active[normalized] = time.monotonic() + self.ttl
            self.address_modes[normalized] = "derived"
            self.last_assigned = normalized
            self.last_assigned_verified = True
            self._persist()
            return normalized
        except Exception as exc:
            self.active.pop(normalized, None)
            self.address_modes.pop(normalized, None)
            subprocess.run(
                ["ip", "-6", "addr", "del", f"{normalized}/128", "dev", self.interface],
                check=False, capture_output=True, text=True,
            )
            raise RuntimeError("unable to persist derived vIP assignment") from exc

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
        self.address_modes.pop(normalized, None)
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


DEFAULT_LAB_ROUTE_STATE = Path(os.environ.get(
    "NLSXNETOS_VIP_LAB_ROUTE_STATE", "/run/nlsxnetos/vip-lab-routes.json"
))
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


class LabTemporaryRouteManager:
    """Own only explicit lab-mode /128 bootstrap routes, with crash cleanup."""

    def __init__(self, state_path: str | Path | None = None, router_id: str | None = None):
        base_path = Path(state_path) if state_path is not None else DEFAULT_LAB_ROUTE_STATE
        if router_id:
            suffix = hashlib.sha256(router_id.encode("utf-8")).hexdigest()[:12]
            base_path = base_path.with_name(f"{base_path.stem}.{suffix}{base_path.suffix}")
        self.state_path = base_path
        self.routes: dict[str, dict] = {}

    @staticmethod
    def _validate_row(row: dict) -> dict:
        from .vip_policy import validate_vip_candidate

        if not isinstance(row, dict) or set(row) != {"vip", "interface", "gateway"}:
            raise ValueError("invalid lab temporary route state row")
        vip = str(validate_vip_candidate(row["vip"], 1))
        interface = row["interface"]
        if not isinstance(interface, str) or not _INTERFACE_RE.fullmatch(interface):
            raise ValueError("invalid lab temporary route interface")
        gateway = row["gateway"]
        if gateway is not None:
            gateway = str(ipaddress.IPv6Address(gateway))
            if ipaddress.IPv6Address(gateway).is_unspecified or ipaddress.IPv6Address(gateway).is_multicast:
                raise ValueError("invalid lab temporary route gateway")
        return {"vip": vip, "interface": interface, "gateway": gateway}

    def _load(self) -> dict[str, dict]:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("lab temporary route state is unreadable") from exc
        if not isinstance(payload, dict) or set(payload) != {"version", "routes"} or payload.get("version") != 1:
            raise RuntimeError("lab temporary route state schema is invalid")
        routes = payload["routes"]
        if not isinstance(routes, dict) or len(routes) > 256:
            raise RuntimeError("lab temporary route state is invalid")
        validated = {}
        for sid, row in routes.items():
            if not isinstance(sid, str) or not re.fullmatch(r"[0-9a-f]{32}", sid):
                raise RuntimeError("lab temporary route session ID is invalid")
            try:
                validated[sid] = self._validate_row(row)
            except (ValueError, TypeError) as exc:
                raise RuntimeError("lab temporary route state row is invalid") from exc
        return validated

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        temp = self.state_path.with_name(
            f"{self.state_path.name}.{os.getpid()}.{id(self)}.tmp"
        )
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"version": 1, "routes": self.routes}, stream,
                          sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.state_path)
            os.chmod(self.state_path, 0o600)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _route_args(action: str, row: dict) -> list[str]:
        args = ["ip", "-6", "route", action, f'{row["vip"]}/128']
        if row["gateway"] is not None:
            args.extend(["via", row["gateway"]])
        args.extend(["dev", row["interface"]])
        return args

    @classmethod
    def _delete_route(cls, row: dict) -> None:
        result = subprocess.run(
            cls._route_args("del", row), check=False, capture_output=True, text=True
        )
        if result.returncode == 0:
            return
        shown = subprocess.run(
            ["ip", "-6", "route", "show", "exact", f'{row["vip"]}/128'],
            check=True, capture_output=True, text=True,
        ).stdout
        if shown.strip():
            raise RuntimeError("lab temporary vIP route remains installed")

    def cleanup_startup(self) -> None:
        """Delete only routes named by this router's validated recovery state."""
        self.routes = self._load()
        failures = []
        for sid, row in list(self.routes.items()):
            try:
                self._delete_route(row)
                self.routes.pop(sid, None)
            except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
                failures.append((sid, type(exc).__name__))
        if failures:
            try:
                self._save()
            finally:
                raise RuntimeError("unable to clean stale lab temporary vIP routes")
        try:
            self.state_path.unlink()
        except FileNotFoundError:
            pass
        self.routes.clear()

    def install(self, session_id: bytes, vip: str, interface: str,
                gateway: str | None) -> None:
        sid = bytes(session_id).hex()
        if len(sid) != 32:
            raise ValueError("lab temporary route session ID must be 16 bytes")
        row = self._validate_row({"vip": vip, "interface": interface, "gateway": gateway})
        if sid in self.routes:
            raise RuntimeError("lab temporary route already exists for this session")
        subprocess.run(
            self._route_args("add", row), check=True, capture_output=True, text=True
        )
        self.routes[sid] = row
        try:
            self._save()
        except Exception as exc:
            try:
                self._delete_route(row)
                self.routes.pop(sid, None)
            except Exception:
                try:
                    self._save()
                except Exception:
                    pass
            raise RuntimeError("unable to persist lab temporary vIP route ownership") from exc

    def release(self, session_id: bytes) -> None:
        sid = bytes(session_id).hex()
        row = self.routes.get(sid)
        if row is None:
            return
        self._delete_route(row)
        self.routes.pop(sid, None)
        self._save()
