from dataclasses import dataclass, field
from nlsxnetos.core.config import CONFIG_DIR
from nlsxnetos.router_ca import store as ca_store
import yaml

CONFIG_PATH = CONFIG_DIR / "nls.yaml"


@dataclass
class PeerConfig:
    id: str
    endpoint: str
    public_key: str
    router_ca_id: int | None = None
    allowed_prefixes: list[str] = field(default_factory=list)


@dataclass
class TunConfig:
    enabled: bool = False
    name: str = "nls0"
    mtu: int = 1400


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
    session_timeout_seconds: int = 300
    peer_block_seconds: int = 60
    auto_router_ca: bool = True
    tun: TunConfig = field(default_factory=TunConfig)
    peers: list[PeerConfig] = field(default_factory=list)


def endpoint(value):
    value = str(value).strip()
    if value.startswith("["):
        if "]:" not in value:
            raise ValueError("IPv6 endpoint must use [address]:port syntax")
        host, port = value.rsplit("]:", 1)
        host = host[1:]
    else:
        if value.count(":") != 1:
            raise ValueError("IPv4 endpoint must use address:port syntax")
        host, port = value.rsplit(":", 1)
    import ipaddress
    try:
        ipaddress.ip_address(host)
        port = int(port)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid NLS endpoint") from exc
    if not 1 <= port <= 65535:
        raise ValueError("NLS endpoint port must be 1..65535")
    return host, port


def load():
    if not CONFIG_PATH.exists():
        return NLSConfig()
    root = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    data = root.get("nls", root)
    td = data.get("tun", {}) or {}
    peers = []
    for raw in data.get("peers", []) or []:
        endpoint(str(raw["endpoint"]))
        peers.append(
            PeerConfig(
                str(raw["id"]),
                str(raw["endpoint"]),
                str(raw["public_key"]),
                int(raw["router_ca_id"]) if raw.get("router_ca_id") is not None else None,
                [str(x) for x in raw.get("allowed_prefixes", [])],
            )
        )

    # Router-CA is the authoritative destination registry once configured.
    # Explicit peers remain supported for controlled/legacy deployments.
    if bool(data.get("auto_router_ca", True)):
        configured_ca_ids = {p.router_ca_id for p in peers if p.router_ca_id is not None}
        for entry in ca_store.active_entries():
            if entry.id in configured_ca_ids:
                continue
            peers.append(
                PeerConfig(
                    f"router-ca-{entry.id}",
                    entry.endpoint,
                    entry.public_key,
                    entry.id,
                    [entry.prefix],
                )
            )

    cfg = NLSConfig(
        bool(data.get("enabled", False)),
        int(data.get("protocol_version", 1)),
        int(data.get("replay_window", 64)),
        int(data.get("max_clock_skew_seconds", 120)),
        str(data.get("listen_address", "::")),
        int(data.get("listen_port", 4789)),
        str(data.get("bind_interface", "")),
        str(data.get("router_id", "nls-router")),
        str(data.get("identity_key", "/var/lib/nlsxnetos/identity/ed25519.key")),
        int(data.get("session_timeout_seconds", 300)),
        int(data.get("peer_block_seconds", 60)),
        bool(data.get("auto_router_ca", True)),
        TunConfig(
            bool(td.get("enabled", False)),
            str(td.get("name", "nls0")),
            int(td.get("mtu", 1400)),
        ),
        peers,
    )
    if cfg.protocol_version != 1:
        raise ValueError("only NLS protocol version 1 is supported")
    if not 1 <= cfg.replay_window <= 4096:
        raise ValueError("replay_window must be 1..4096")
    if not 1 <= cfg.listen_port <= 65535:
        raise ValueError("listen_port must be 1..65535")
    if cfg.tun.mtu < 576:
        raise ValueError("TUN MTU must be >= 576")
    return cfg
