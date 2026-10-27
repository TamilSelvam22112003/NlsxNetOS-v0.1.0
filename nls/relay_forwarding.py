"""Authenticated per-hop NLS forwarding decision logic.

This module deliberately does not open sockets or change kernel routes. It
validates an incoming hop envelope and creates the next hop envelope while
preserving the final server IP as the outer destination. The caller must use a
transparent socket, enforce an operator-configured route through the selected
next hop, and bind the actual WAN source address.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .relay_envelope import RelayEnvelopeError, open_relay_layer, seal_relay_layer
from .replay import ReplayWindow


class RelayForwardingError(ValueError):
    """Raised when a hop cannot safely forward an authenticated envelope."""


@dataclass(frozen=True)
class HopContext:
    key: bytes
    token: bytes
    next_sequence: int
    replay_window: ReplayWindow


@dataclass(frozen=True)
class ForwardPlan:
    outer_destination: str
    outer_destination_port: int
    next_hop_address: str
    next_hop_port: int
    sequence: int
    packet: bytes


def prepare_forward(
    packet: bytes,
    *,
    observed_outer_source: str,
    outer_destination: str,
    outer_destination_port: int,
    local_wan_locator: str,
    listen_port: int,
    inbound: HopContext,
    outbound: HopContext,
    configured_next_hop: str,
    configured_next_hop_port: int,
) -> ForwardPlan:
    """Validate one hop and re-wrap its opaque inner envelope for the next hop.

    The outer destination remains the final server address. The sender's
    source locator is inside AEAD ciphertext and must match the observed outer
    source address. No inner endpoint ciphertext is decrypted here.
    """
    try:
        source = ipaddress.ip_address(observed_outer_source)
        final_destination = ipaddress.ip_address(outer_destination)
        local_locator = ipaddress.ip_address(local_wan_locator)
        next_locator = ipaddress.ip_address(configured_next_hop)
    except ValueError as exc:
        raise RelayForwardingError("outer source, destination, and relay locators must be IP literals") from exc
    if source.is_unspecified or source.is_multicast:
        raise RelayForwardingError("invalid observed outer source")
    if final_destination.is_unspecified or final_destination.is_multicast:
        raise RelayForwardingError("invalid final server destination")
    if local_locator.is_unspecified or local_locator.is_multicast:
        raise RelayForwardingError("invalid local WAN locator")
    if next_locator.is_unspecified or next_locator.is_multicast:
        raise RelayForwardingError("invalid configured next-hop locator")
    if not 1 <= outer_destination_port <= 65535 or not 1 <= listen_port <= 65535:
        raise RelayForwardingError("invalid outer destination or NLS listen port")
    if not 1 <= configured_next_hop_port <= 65535:
        raise RelayForwardingError("invalid configured next-hop port")
    if outbound.next_sequence < 0 or outbound.next_sequence >= 2**64:
        raise RelayForwardingError("outbound sequence exhausted; rekey before wraparound")

    try:
        layer = open_relay_layer(
            inbound.key,
            packet,
            expected_hop_token=inbound.token,
        )
    except RelayEnvelopeError as exc:
        raise RelayForwardingError(str(exc)) from exc

    if not inbound.replay_window.can_accept(layer.sequence):
        raise RelayForwardingError("NLS relay replay detected")
    if layer.previous_hop_source_locator != str(source):
        raise RelayForwardingError("encrypted previous-hop locator does not match observed outer source")
    if layer.next_hop_address != str(local_locator) or layer.next_hop_port != listen_port:
        raise RelayForwardingError("envelope is not addressed to this relay's configured NLS listener")
    if not inbound.replay_window.mark(layer.sequence):
        raise RelayForwardingError("NLS relay replay detected")

    try:
        outgoing = seal_relay_layer(
            outbound.key,
            outbound.token,
            outbound.next_sequence,
            str(next_locator),
            configured_next_hop_port,
            layer.inner_envelope,
            previous_hop_source_locator=str(local_locator),
        )
    except RelayEnvelopeError as exc:
        raise RelayForwardingError(str(exc)) from exc

    return ForwardPlan(
        outer_destination=str(final_destination),
        outer_destination_port=outer_destination_port,
        next_hop_address=str(next_locator),
        next_hop_port=configured_next_hop_port,
        sequence=outbound.next_sequence,
        packet=outgoing,
    )
