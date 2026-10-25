from dataclasses import dataclass, field
from kernel.config import CONFIG_DIR
import yaml


CONFIG_PATH = CONFIG_DIR / "nls.yaml"


@dataclass
class PeerConfig:
    id: str
    endpoint: str
    public_key: str
    router_ca_id: int | None = None
    allowed_prefixes: list[str] = field(default_factory=list)
    encryption_public_key: str | None = None


@dataclass
class TunConfig:
    enabled: bool = False
    name: str = "nls0"
    mtu: int = 1400


@dataclass
class NLSConfig:
    enabled: bool = False
    protocol_version: int = 1
    replay_window: int = 128
    max_clock_skew_seconds: int = 120
    listen_address: str = "::"
    listen_port: int = 4789
    bind_interface: str = ""
    router_id: str = "nls-router"
    identity_key: str = "/var/lib/nlsxnetos/identity/ed25519.key"
    encryption_private_key: str = "/var/lib/nlsxnetos/identity/rsa-encryption.pem"
    session_timeout_seconds: int = 300
    peer_block_seconds: int = 60
    tun: TunConfig = field(default_factory=TunConfig)
    peers: list[PeerConfig] = field(default_factory=list)
    trust_mode: str = "ca"
    stale_grace_seconds: int = 0
    enforce_inner_source_prefix: bool = True
    rekey_packet_limit: int = 1 << 32
    rekey_seconds: int = 3600
    rekey_overlap_seconds: int = 5
    metadata_mode: str = "source-destination"


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
    # Stage 7: derived vIPs are never kernel addresses or routes.
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
                str(raw["encryption_public_key"])
                if raw.get("encryption_public_key")
                else None,
            )
        )


    cfg = NLSConfig(
        bool(data.get("enabled", False)),
        int(data.get("protocol_version", 1)),
        int(data.get("replay_window", 128)),
        int(data.get("max_clock_skew_seconds", 120)),
        str(data.get("listen_address", "::")),
        int(data.get("listen_port", 4789)),
        str(data.get("bind_interface", "")),
        str(data.get("router_id", "nls-router")),
        str(data.get("identity_key", "/var/lib/nlsxnetos/identity/ed25519.key")),
        str(data.get("encryption_private_key", "/var/lib/nlsxnetos/identity/rsa-encryption.pem")),
        int(data.get("session_timeout_seconds", 300)),
        int(data.get("peer_block_seconds", 60)),
        TunConfig(
            bool(td.get("enabled", False)),
            str(td.get("name", "nls0")),
            int(td.get("mtu", 1400)),
        ),
        peers,
        str(data.get("trust_mode", "ca")),
        int(data.get("stale_grace_seconds", 0)),
        bool(data.get("enforce_inner_source_prefix", True)),
        int(data.get("rekey_packet_limit", 1 << 32)),
        int(data.get("rekey_seconds", 3600)),
        int(data.get("rekey_overlap_seconds", 5)),
        str(data.get("metadata_mode", "source-destination")),
    )
    if cfg.metadata_mode not in ("source-only", "source-destination"):
        raise ValueError("metadata_mode must be source-only or source-destination")
    if cfg.trust_mode not in ("ca", "offline"):
        raise ValueError("trust_mode must be ca or offline")
    if cfg.stale_grace_seconds < 0 or cfg.stale_grace_seconds > 600:
        raise ValueError("stale_grace_seconds must be 0..600")
    if not 2 <= cfg.rekey_packet_limit <= (1 << 32):
        raise ValueError("rekey_packet_limit must be 2..2^32")
    if not 1 <= cfg.rekey_seconds <= 86400:
        raise ValueError("rekey_seconds must be 1..86400")
    if not 1 <= cfg.rekey_overlap_seconds <= 60:
        raise ValueError("rekey_overlap_seconds must be 1..60")
    if cfg.protocol_version != 1:
        raise ValueError("only NLS protocol version 1 is supported")
    if not 1 <= cfg.replay_window <= 4096:
        raise ValueError("replay_window must be 1..4096")
    if not 1 <= cfg.listen_port <= 65535:
        raise ValueError("NLS endpoint port must be 1..65535")
    if cfg.tun.mtu < 576:
        raise ValueError("TUN MTU must be >= 576")
    return cfg
