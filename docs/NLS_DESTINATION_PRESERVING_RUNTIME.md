# Destination-preserving NLS runtime integration

Status: **runtime integration in progress; not enabled by default**.

The intended data path keeps the final server IP as the outer IPv6 destination while each emitting relay uses its own WAN source address. This requires the operator's routing topology to carry the marked NLS UDP packets through the configured relay chain; IP routing does not automatically select an NLS chain.

## Implemented foundation in this branch

- Linux transparent UDP socket setup with IP_TRANSPARENT/IPV6_TRANSPARENT.
- Original destination and ingress interface extraction from packet-info ancillary data.
- Fail-closed handling when destination metadata is absent or truncated.
- Narrow nftables TPROXY rules for the configured UDP port and dedicated fwmark policy-routing tables.
- Teardown removes only the dedicated NLS nftables table and matching policy-routing entries.

## Not yet complete

This module is not yet called by `NLSDaemon`. The daemon still uses NLE1, and the new NLR1 envelope is not wired into its session/data path. Do not enable these kernel rules as a claim of protocol compliance. Before runtime activation, the next implementation step must add authenticated per-hop session/key selection, source-locator validation against the actual ingress source, replay-window enforcement for NLR1, final-destination route selection, end-to-end endpoint encryption/authentication, server delivery, and return-path handling.

## Operator safety

- Run only in a lab or on a dedicated router with console access.
- The rules intercept UDP to the configured NLS port; use a dedicated port and dedicated table.
- Configure the network route so packets continue to the next authorized relay while retaining the final server destination.
- Verify with IPv6 WAN captures on every hop. Passing unit tests does not prove correct transit routing or metadata confidentiality.
