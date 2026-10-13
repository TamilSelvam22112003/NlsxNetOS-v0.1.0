import ipaddress
import pytest

from nls.vip import generate_temporary_vip


def test_temporary_vip_is_in_configured_ula64_and_repeatable_for_nonce():
    identity = b"router-identity-material-012345"
    nonce = b"fixed-test-nonce-material-12345"
    first, returned_nonce = generate_temporary_vip(identity, "fd42:4e4c:5300:1::/64", nonce=nonce)
    second, _ = generate_temporary_vip(identity, "fd42:4e4c:5300:1::/64", nonce=nonce)
    assert first == second
    assert returned_nonce == nonce
    assert ipaddress.IPv6Address(first) in ipaddress.IPv6Network("fd42:4e4c:5300:1::/64")


def test_temporary_vip_changes_with_nonce():
    identity = b"router-identity-material-012345"
    first, _ = generate_temporary_vip(identity, "fd42:4e4c:5300:1::/64", nonce=b"a" * 32)
    second, _ = generate_temporary_vip(identity, "fd42:4e4c:5300:1::/64", nonce=b"b" * 32)
    assert first != second


def test_rejects_non_ula_or_non_64_prefix():
    with pytest.raises(ValueError):
        generate_temporary_vip(b"x" * 20, "2001:db8::/64")
    with pytest.raises(ValueError):
        generate_temporary_vip(b"x" * 20, "fd42:4e4c:5300::/48")


def test_handshake_vip_derivation_is_keyed_and_peer_scoped():
    from nls.vip import derive_temporary_vip

    secret = b"s" * 32
    nonce = b"n" * 32
    first = derive_temporary_vip(secret, "router-a", "router-b", nonce)
    repeat = derive_temporary_vip(secret, "router-a", "router-b", nonce)
    other_peer = derive_temporary_vip(secret, "router-a", "router-c", nonce)
    assert first == repeat
    assert first != other_peer
    assert ipaddress.IPv6Address(first) in ipaddress.IPv6Network("fd42:4e4c:5300::/48")


def test_handshake_vip_rejects_short_secret_or_nonce():
    from nls.vip import derive_temporary_vip

    with pytest.raises(ValueError):
        derive_temporary_vip(b"short", "router-a", "router-b", b"n" * 32)
    with pytest.raises(ValueError):
        derive_temporary_vip(b"s" * 32, "router-a", "router-b", b"short")
