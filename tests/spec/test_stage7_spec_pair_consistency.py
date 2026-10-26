from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
NETOS_SPEC = REPO_ROOT / "docs" / "nls" / "MASTER_SPEC.md"
CORE_SPEC = REPO_ROOT / "core" / "docs" / "nls" / "MASTER_SPEC.md"


def test_both_specs_define_primary_locator_and_port_as_one_endpoint():
    netos = NETOS_SPEC.read_text(encoding="utf-8")
    core = CORE_SPEC.read_text(encoding="utf-8")

    assert "wan_endpoints[0]" in netos
    assert "wan_endpoints[0]" in core
    assert "UDP port comes from that same endpoint" in netos
    assert (
        "UDP port are taken from the same signed, ordered "
        + chr(96)
        + "wan_endpoints[0]"
        + chr(96)
        + " entry"
    ) in core


def test_both_specs_prohibit_derived_vip_as_outer_locator_or_route():
    netos = NETOS_SPEC.read_text(encoding="utf-8")
    core = CORE_SPEC.read_text(encoding="utf-8")

    assert "MUST NOT be used as an outer IPv6 source or destination" in netos
    assert "MUST NOT be used as an outer source/destination address" in core
    assert (
        "MUST NOT install a route for the derived " + chr(96) + "vip" + chr(96)
    ) in netos
    assert (
        "MUST NOT install a route for the derived " + chr(96) + "vip" + chr(96)
    ) in core


def test_both_specs_define_the_same_m1_to_m4_direction():
    netos = NETOS_SPEC.read_text(encoding="utf-8")
    core = CORE_SPEC.read_text(encoding="utf-8")

    assert "M1 (S to D)" in netos
    assert "M2 (D to S)" in netos
    assert (
        "M3 uses the same outer locator direction as M1; M4 uses the same outer locator direction as M2."
    ) in netos
    assert (
        "M1 travels S to D; M2 travels D to S; M3 travels S to D; M4 travels D to S."
    ) in core
