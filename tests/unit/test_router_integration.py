import base64

from cryptography.hazmat.primitives.asymmetric import rsa

from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64
from nlsxnetos.nls.rsa_signing import public_key_b64 as rsa_signing_public_key_b64


def make_entry(identifier, prefix, label, endpoint):
    from nlsxnetos.router_ca.models import RouterCAEntry
    identity = base64.b64encode(bytes([identifier]) * 32).decode()
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return RouterCAEntry(
        identifier,
        prefix,
        label,
        identity,
        endpoint,
        encryption_public_key=rsa_public_key_b64(encryption),
        signing_public_key=rsa_signing_public_key_b64(signing),
    )


def test_router_ca_entry_requires_valid_nls_identity():
    entry = make_entry(10, "2001:db8:200::/48", "destination", "[2001:db8::10]:4789")
    entry.validate()
    assert entry.nls_ready


def test_router_ca_lookup_is_longest_prefix(monkeypatch):
    from nlsxnetos.router_ca import store
    entries = [
        make_entry(1, "2001:db8::/32", "wide", "[2001:db8::1]:4789"),
        make_entry(2, "2001:db8:200::/48", "specific", "[2001:db8::2]:4789"),
    ]
    monkeypatch.setattr(store, "load", lambda: entries)
    assert store.lookup("2001:db8:200::1234").id == 2
    assert store.lookup("2001:db8:300::1234").id == 1


def test_nls_config_auto_builds_router_ca_peer(monkeypatch, tmp_path):
    import nlsxnetos.nls.config as cfgmod
    entries = [make_entry(7, "203.0.113.0/24", "remote", "203.0.113.1:4789")]
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "nls.yaml")
    (tmp_path / "nls.yaml").write_text(
        "nls:\n  enabled: true\n  auto_router_ca: true\n  tun:\n    enabled: true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cfgmod.ca_store, "active_entries", lambda: entries)
    cfg = cfgmod.load()
    assert cfg.peers[0].router_ca_id == 7
    assert cfg.peers[0].allowed_prefixes == ["203.0.113.0/24"]
    assert cfg.peers[0].signing_public_key
