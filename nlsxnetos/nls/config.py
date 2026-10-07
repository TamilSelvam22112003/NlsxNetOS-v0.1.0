from dataclasses import dataclass, field
import yaml
from nlsxnetos.core.config import CONFIG_DIR
from nlsxnetos.router_ca import store as ca_store
CONFIG_PATH = CONFIG_DIR / "nls.yaml"
@dataclass
class PeerConfig:
    id: str
    endpoint: str
    public_key: str
    router_ca_id: int | None = None
    allowed_prefixes: list[str] = field(default_factory=list)
    encryption_public_key: str | None = None
    signing_public_key: str | None = None
@dataclass
class TunConfig:
    enabled: bool = False
    name: str = "nls0"
    mtu: int = 576
@dataclass
class NLSConfig:
    enabled: bool = False
    protocol_version: int = 1
    replay_window: int = 64
    max_clock_skew_seconds: int = 120
    listen_address: str = "::"
    listen_port: int = 4789
    bind_interface: str = ""
    router_id: str = "nls-router"
    identity_key: str = "/var/lib/nlsxnetos/identity/ed25519.key"
    encryption_private_key: str = "/var/lib/nlsxnetos/identity/rsa-encryption.pem"
    signing_private_key: str = "/var/lib/nlsxnetos/identity/rsa-signing.pem"
    session_timeout_seconds: int = 300
    peer_block_seconds: int = 60
    auto_router_ca: bool = True
    router_ca_server_url: str = ""
    router_ca_ca_file: str = ""
    router_ca_timeout_seconds: int = 5
    router_ca_bearer_token: str = ""
    advertised_endpoint: str = ""
    tun: TunConfig = field(default_factory=TunConfig)
    peers: list[PeerConfig] = field(default_factory=list)
def endpoint(value):
    value = str(value).strip()
    if value.startswith("["):
        if "]:" not in value: raise ValueError("IPv6 endpoint must use [address]:port syntax")
        host, port = value.rsplit("]:", 1); host = host[1:]
    else:
        if value.count(":") != 1: raise ValueError("IPv4 endpoint must use address:port syntax")
        host, port = value.rsplit(":", 1)
    import ipaddress
    try: ipaddress.ip_address(host); port = int(port)
    except (ValueError, TypeError) as exc: raise ValueError("invalid NLS endpoint") from exc
    if not 1 <= port <= 65535: raise ValueError("NLS endpoint port must be 1..65535")
    return host, port
def load():
    if not CONFIG_PATH.exists(): return NLSConfig()
    root = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    data = root.get("nls", root); ca_data = data.get("router_ca", {}) or {}; td = data.get("tun", {}) or {}
    peers = []
    for raw in data.get("peers", []) or []:
        endpoint(str(raw["endpoint"]))
        peers.append(PeerConfig(str(raw["id"]), str(raw["endpoint"]), str(raw["public_key"]),
            int(raw["router_ca_id"]) if raw.get("router_ca_id") is not None else None,
            [str(x) for x in raw.get("allowed_prefixes", [])],
            str(raw["encryption_public_key"]) if raw.get("encryption_public_key") else None,
            str(raw["signing_public_key"]) if raw.get("signing_public_key") else None))
        if peers[-1].encryption_public_key and not peers[-1].signing_public_key:
            raise ValueError(f"NLS peer {peers[-1].id} must define a distinct RSA signing public key")
    if bool(data.get("auto_router_ca", True)):
        configured = {p.router_ca_id for p in peers if p.router_ca_id is not None}
        for entry in ca_store.active_entries():
            if entry.id not in configured:
                peers.append(PeerConfig(entry.label, entry.endpoint, entry.public_key, entry.id,
                    [entry.prefix], entry.encryption_public_key, entry.signing_public_key))
    return NLSConfig(bool(data.get("enabled", False)), int(data.get("protocol_version", 1)),
        int(data.get("replay_window", 64)), int(data.get("max_clock_skew_seconds", 120)),
        str(data.get("listen_address", "::")), int(data.get("listen_port", 4789)), str(data.get("bind_interface", "")),
        str(data.get("router_id", "nls-router")), str(data.get("identity_key", "/var/lib/nlsxnetos/identity/ed25519.key")),
        str(data.get("encryption_private_key", "/var/lib/nlsxnetos/identity/rsa-encryption.pem")),
        str(data.get("signing_private_key", "/var/lib/nlsxnetos/identity/rsa-signing.pem")),
        int(data.get("session_timeout_seconds", 300)), int(data.get("peer_block_seconds", 60)),
        bool(data.get("auto_router_ca", True)), str(ca_data.get("server_url", "")), str(ca_data.get("ca_file", "")),
        int(ca_data.get("timeout_seconds", 5)), str(ca_data.get("bearer_token", "")), str(data.get("advertised_endpoint", "")),
        TunConfig(bool(td.get("enabled", False)), str(td.get("name", "nls0")), int(td.get("mtu", 576)),), peers)
