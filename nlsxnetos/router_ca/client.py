from __future__ import annotations

import json
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

from .models import RouterCAEntry


@dataclass
class RouterCAClient:
    """Client-side interface to an external Router-CA service.

    This module intentionally contains no CA issuance, signing, storage-authority,
    or certificate-management server logic. The Router-CA repository owns those
    responsibilities.
    """

    base_url: str
    timeout: int = 5
    ca_file: str | None = None
    bearer_token: str | None = None

    def _url(self, path: str, query: dict | None = None) -> str:
        base = self.base_url.rstrip("/") + "/"
        value = urljoin(base, path.lstrip("/"))
        if query:
            value += ("&" if "?" in value else "?") + urlencode(query)
        return value

    def _context(self):
        return ssl.create_default_context(cafile=self.ca_file) if self.ca_file else ssl.create_default_context()

    def _request(self, method: str, path: str, payload: dict | None = None, query: dict | None = None) -> dict:
        body = None
        headers = {"Accept": "application/json", "User-Agent": "NlsxNetOS-Router/0.1"}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        request = Request(self._url(path, query), data=body, headers=headers, method=method)
        with urlopen(request, timeout=self.timeout, context=self._context()) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"Router-CA HTTP status {response.status}")
            data = json.loads(response.read().decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Router-CA response must be a JSON object")
        return data

    @staticmethod
    def _entry(data: dict) -> RouterCAEntry:
        record = data.get("router", data)
        required = ("id", "prefix", "label", "endpoint", "public_key", "encryption_public_key", "signing_public_key")
        missing = [key for key in required if not record.get(key)]
        if missing:
            raise ValueError("Router-CA response missing: " + ", ".join(missing))
        entry = RouterCAEntry(
            int(record["id"]),
            str(record["prefix"]),
            str(record["label"]),
            str(record["public_key"]),
            str(record["endpoint"]),
            str(record["encryption_public_key"]),
            str(record["signing_public_key"]),
            str(record["certificate"]) if record.get("certificate") else None,
            int(record["timestamp"]) if record.get("timestamp") is not None else None,
        )
        entry.validate()
        return entry

    def resolve(self, destination: str) -> RouterCAEntry:
        data = self._request("GET", "v1/routers/resolve", query={"ip": destination})
        return self._entry(data)

    def resolve_identity(self, public_key: str) -> RouterCAEntry:
        """Resolve the authoritative router record for an initiator identity key."""
        if not public_key:
            raise ValueError("Router-CA identity lookup requires a public key")
        data = self._request(
            "GET",
            "v1/routers/resolve-identity",
            query={"public_key": public_key},
        )
        return self._entry(data)

    def resolve_next_hop(self, address: str) -> RouterCAEntry:
        """Resolve an OSPF/Linux transport next-hop address to its router record."""
        data = self._request("GET", "v1/routers/resolve-next-hop", query={"ip": address})
        return self._entry(data)

    def get_router(self, router_id: int) -> RouterCAEntry:
        data = self._request("GET", f"v1/routers/{int(router_id)}")
        return self._entry(data)

    def register(self, *, router_id: str, endpoint: str, public_key: str,
                 encryption_public_key: str, signing_public_key: str, timestamp: int | None = None) -> dict:
        payload = {
            "router_id": router_id,
            "endpoint": endpoint,
            "public_key": public_key,
            "encryption_public_key": encryption_public_key,
            "signing_public_key": signing_public_key,
            "timestamp": int(time.time()) if timestamp is None else int(timestamp),
        }
        return self._request("POST", "v1/routers/register", payload)

    def health(self) -> bool:
        try:
            self._request("GET", "v1/health")
            return True
        except Exception:
            return False
