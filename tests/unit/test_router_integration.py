import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64
from nlsxnetos.nls.rsa_signing import public_key_b64 as rsa_signing_public_key_b64


def test_router_ca_entry_requires_valid_nls_identity():
    from nlsxnetos.router_ca.models import RouterCAEntry

    key = base64.b64encode(bytes(32)).decode()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    entry = RouterCAEntry(10, "2001:db8:200::/48", "destination", key, "[2001:db8::10]:4789", rsa_public_key_b64(rsa_key), rsa_signing_public_key_b64(signing_key))
    entry.validate()
    assert entry.nls_ready


def test_router_ca_lookup_is_longest_prefix():
    from nlsxnetos.router_ca import store
    from nlsxnetos.router_ca.models import RouterCAEntry

    key = base64.b64encode(bytes(32)).decode()
    entries = [
        RouterCAEntry(1, "2001:db8::/32", "wide", key, "[2001:db8::1]:4789", rsa_public_key_b64(rsa.generate_private_key(public_exponent=65537, key_size=3072)), rsa_signing_public_key_b64(rsa.generate_private_key(public_exponent=65537, key_size=3072))),
        RouterCAEntry(2, "2001:db8:200::/48", "specific", key, "[2001:db8::2]:4789", rsa_public_key_b64(rsa.generate_private_key(public_exponent=65537, key_size=3072)), rsa_signing_public_key_b64(rsa.generate_private_key(public_exponent=65537, key_size=3072))),
    ]
    old = store.load
    store.load = lambda: entries
    try:
        assert store.lookup("2001:db8:200::1234").id == 2
        assert store.lookup("2001:db8:300::1234").id == 1
    finally:
        store.load = old


def test_nls_config_auto_builds_router_ca_peer(monkeypatch, tmp_path):
    import nlsxnetos.nls.config as cfgmod
    from nlsxnetos.router_ca.models import RouterCAEntry

    key = base64.b64encode(bytes(32)).decode()
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "nls.yaml")
    (tmp_path / "nls.yaml").write_text("nls:
  enabled: true
  auto_router_ca: true
  tun:
    enabled: true
", encoding="utf-8")
    monkeypatch.setattr(
        cfgmod.ca_store,
        "active_entries",
        lambda: [RouterCAEntry(7, "203.0.113.0/24", "remote", key, "203.0.113.1:4789", rsa_public_key_b64(rsa.generate_private_key(public_exponent=65537, key_size=3072)), rsa_signing_public_key_b64(rsa.generate_private_key(public_exponent=65537, key_size=3072)))],
    )
    cfg = cfgmod.load()
    assert cfg.peers[0].router_ca_id == 7
    assert cfg.peers[0].allowed_prefixes == ["203.0.113.0/24"]
