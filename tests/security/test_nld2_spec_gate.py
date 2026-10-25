"""Regression gate for data-plane framing specified in docs/nls/MASTER_SPEC.md.

The test is intentionally strict-xfail on feat/nls-v1 until the NLD2 wire
format is implemented on that branch. It becomes a CI failure (XPASS) if the
legacy counter-first payload unexpectedly changes without this test being
reviewed and the full NLD2 contract being validated.
"""
import ipaddress

from nls.source_token import seal_source_token_payload


def test_source_token_payload_uses_nld2_wire_magic():
    key = b"K" * 32
    iv_prefix = b"IVP2"
    source = ipaddress.IPv6Address("2001:db8::1")
    destination = ipaddress.IPv6Address("2001:db8::2")
    # A minimal IPv6 packet: fixed header only, no payload.
    inner_packet = (
        bytes.fromhex("6000000000003b40")
        + source.packed
        + destination.packed
    )

    wire = seal_source_token_payload(
        key,
        iv_prefix,
        0,
        source,
        destination,
        inner_packet,
        metadata_mode="source-destination",
    )

    assert wire.startswith(b"NLD2")
