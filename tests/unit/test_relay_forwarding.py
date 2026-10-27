import ipaddress

import pytest

from nls.relay_envelope import open_relay_layer, seal_relay_layer
from nls.relay_forwarding import HopContext, RelayForwardingError, prepare_forward
from nls.replay import ReplayWindow

KEY_IN = bytes.fromhex("11" * 32)
KEY_OUT = bytes.fromhex("22" * 32)
TOKEN_IN = bytes.fromhex("aa" * 16)
TOKEN_OUT = bytes.fromhex("bb" * 16)
R1 = "2001:db8:1::1"
R2 = "2001:db8:2::1"
R3 = "2001:db8:3::1"
SERVER = "2001:db8:ffff::80"
INNER = b"opaque endpoint-encrypted envelope with source and payload canaries"


def contexts():
    return (
        HopContext(KEY_IN, TOKEN_IN, 0, ReplayWindow(64)),
        HopContext(KEY_OUT, TOKEN_OUT, 19, ReplayWindow(64)),
    )


def incoming(source=R1, target=R2, sequence=7):
    return seal_relay_layer(
        KEY_IN, TOKEN_IN, sequence, target, 4789, INNER,
        previous_hop_source_locator=source,
    )


def forward(packet=None, *, source=R1, target=R2):
    inbound, outbound = contexts()
    return prepare_forward(
        packet if packet is not None else incoming(),
        observed_outer_source=source,
        outer_destination=SERVER,
        outer_destination_port=4789,
        local_wan_locator=target,
        listen_port=4789,
        inbound=inbound,
        outbound=outbound,
        configured_next_hop=R3,
        configured_next_hop_port=4789,
    ), inbound, outbound


def test_forward_preserves_final_destination_and_rewraps_opaque_inner():
    plan, inbound, outbound = forward()
    assert plan.outer_destination == SERVER
    assert plan.outer_destination_port == 4789
    assert plan.next_hop_address == R3
    assert plan.next_hop_port == 4789
    assert ipaddress.ip_address(R1).packed not in plan.packet
    assert ipaddress.ip_address(R2).packed not in plan.packet
    next_layer = open_relay_layer(KEY_OUT, plan.packet, expected_hop_token=TOKEN_OUT, expected_sequence=19)
    assert next_layer.previous_hop_source_locator == R2
    assert next_layer.next_hop_address == R3
    assert next_layer.inner_envelope == INNER
    assert inbound.replay_window.highest == 7


def test_forward_rejects_source_locator_spoof():
    with pytest.raises(RelayForwardingError, match="does not match"):
        forward(source="2001:db8:9::9")


def test_forward_rejects_wrong_local_destination_locator():
    with pytest.raises(RelayForwardingError, match="not addressed"):
        forward(target="2001:db8:8::1")


def test_forward_rejects_replay():
    inbound, outbound = contexts()
    packet = incoming(sequence=7)
    kwargs = dict(
        observed_outer_source=R1, outer_destination=SERVER,
        outer_destination_port=4789, local_wan_locator=R2,
        listen_port=4789, inbound=inbound, outbound=outbound,
        configured_next_hop=R3, configured_next_hop_port=4789,
    )
    prepare_forward(packet, **kwargs)
    with pytest.raises(RelayForwardingError, match="replay"):
        prepare_forward(packet, **kwargs)


def test_forward_rejects_invalid_final_destination():
    inbound, outbound = contexts()
    with pytest.raises(RelayForwardingError, match="final server destination"):
        prepare_forward(
            incoming(), observed_outer_source=R1, outer_destination="::",
            outer_destination_port=4789, local_wan_locator=R2, listen_port=4789,
            inbound=inbound, outbound=outbound, configured_next_hop=R3,
            configured_next_hop_port=4789,
        )
