import base64
import hashlib
import ipaddress
import json
from types import SimpleNamespace

import pytest

from nls import vip
from nls.source_token import address_policy_valid


def _record(original_ip, certificate, spki):
    return {
        "originalIP": original_ip,
        "certificate_der_b64": base64.b64encode(certificate).decode("ascii"),
        "ed25519_public_key_spki_der_b64": base64.b64encode(spki).decode("ascii"),
    }


def _expected(source, destination, nonce, bucket):
    fields = (
        b"NLS-vIP-v1",
        ipaddress.IPv6Address(destination["originalIP"]).packed,
        base64.b64decode(destination["certificate_der_b64"]),
        base64.b64decode(destination["ed25519_public_key_spki_der_b64"]),
        ipaddress.IPv6Address(source["originalIP"]).packed,
        base64.b64decode(source["certificate_der_b64"]),
        base64.b64decode(source["ed25519_public_key_spki_der_b64"]),
        nonce,
        bucket.to_bytes(8, "big"),
    )
    encoded = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return ipaddress.IPv6Address(hashlib.sha512(encoded).digest()[:16])


def test_vip_derivation_matches_normative_field_order_and_length_prefixing():
    source = _record("fd00::1", b"source-cert-der", b"source-spki-der")
    destination = _record("fd00::2", b"destination-cert-der", b"destination-spki-der")
    nonce = bytes(range(32))
    bucket = 60_000_000
    assert vip.derive_vip_candidate(source, destination, nonce, bucket) == _expected(
        source, destination, nonce, bucket
    )


def test_vip_derivation_changes_with_nonce_or_time_bucket():
    source = _record("fd00::1", b"source-cert-der", b"source-spki-der")
    destination = _record("fd00::2", b"destination-cert-der", b"destination-spki-der")
    nonce = bytes(range(32))
    base = vip.derive_vip_candidate(source, destination, nonce, 60_000_000)
    assert vip.derive_vip_candidate(source, destination, bytes(reversed(range(32))), 60_000_000) != base
    assert vip.derive_vip_candidate(source, destination, nonce, 60_000_001) != base


@pytest.mark.parametrize(
    ("nonce", "bucket", "version"),
    [
        (b"short", 1, 1),
        (bytes(32), -1, 1),
        (bytes(32), 1 << 64, 1),
        (bytes(32), 1, 2),
    ],
)
def test_vip_derivation_rejects_invalid_inputs(nonce, bucket, version):
    source = _record("fd00::1", b"source-cert-der", b"source-spki-der")
    destination = _record("fd00::2", b"destination-cert-der", b"destination-spki-der")
    with pytest.raises(ValueError):
        vip.derive_vip_candidate(source, destination, nonce, bucket, version)


def test_assign_derived_vip_persists_explicit_ownership(tmp_path, monkeypatch):
    address = "2001:4860::1"
    assert address_policy_valid(address, 1)
    monkeypatch.setattr(vip, "_run", lambda _args: None)
    monkeypatch.setattr(
        vip.subprocess,
        "run",
        lambda args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=f"inet6 {address}/128 scope global\n" if args[3] == "show" else "",
        ),
    )
    manager = vip.VIPManager("wan0", state_path=tmp_path / "vip-state.json")
    assert manager.assign_derived(address) == address
    state = json.loads(manager.state_path.read_text(encoding="utf-8"))
    assert state["version"] == 2
    assert state["addresses"] == [address]
    assert state["derived_addresses"] == [address]
    assert manager.derived_addresses == {address}


def test_assign_derived_vip_rejects_policy_excluded_address(tmp_path, monkeypatch):
    manager = vip.VIPManager("wan0", state_path=tmp_path / "vip-state.json")
    monkeypatch.setattr(vip, "_run", lambda _args: pytest.fail("must not assign excluded vIP"))
    with pytest.raises(ValueError, match="policy v1"):
        manager.assign_derived("2001:db8::1")
