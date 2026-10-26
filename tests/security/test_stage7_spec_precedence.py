from pathlib import Path

SPEC_PATH = Path(__file__).resolve().parents[2] / "docs" / "nls" / "MASTER_SPEC.md"


def test_stage7_locator_precedence_is_normative():
    spec = SPEC_PATH.read_text(encoding="utf-8")
    assert "## Normative precedence amendment: Stage 7 routable-locator bootstrap" in spec
    assert "authenticated primary WAN locator" in spec
    assert "The derived `vip` is cryptographic handshake context only" in spec
    assert "MUST NOT be used as an outer IPv6 source or destination" in spec
    assert "MUST NOT install a route for the derived `vip`" in spec


def test_legacy_derived_vip_outer_addressing_is_not_normative():
    spec = SPEC_PATH.read_text(encoding="utf-8")
    forbidden_legacy_rules = (
        "outer source = derived vIP",
        "outer destination = derived vIP",
        "outer source address MUST equal the `vip` field",
        "compare the result with the M1 outer source address",
        "MUST be assigned/recognized as the outer source address",
        "MAY install a temporary IPv6 /128 route for the derived vIP",
        "S picks a fresh random /128 vIP and assigns it to its WAN interface",
    )
    for rule in forbidden_legacy_rules:
        assert rule not in spec, f"superseded Stage 7 rule remains in MASTER_SPEC.md: {rule}"


def test_legacy_temporary_vip_route_switch_is_prohibited():
    spec = SPEC_PATH.read_text(encoding="utf-8")
    assert "The legacy configuration key `vip.lab_temporary_route.enabled` is deprecated and MUST remain false." in spec
    assert "The selected Stage 7 v1 profile forbids temporary derived-vIP routes even in lab mode." in spec
    assert "a vIP-based endpoint transition" in spec
