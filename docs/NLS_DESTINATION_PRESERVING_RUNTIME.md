# Destination-preserving NLS runtime integration

Status: **runtime integration in progress; not enabled by default**.

The intended data path keeps the final server IP as the outer IPv6 destination while each emitting relay uses its own WAN source address. This requires the operator's routing topology to carry the marked NLS UDP packets through the configured relay chain; IP routing does not automatically select an NLS chain.

## Implemented foundation in this branch

- Linux transparent UDP socket setup with IP_TRANSPARENT/IPV6_TRANSPARENT.
- Original destination and ingress interface extraction from packet-info ancillary data.
- Source-selected transparent sends so the emitting relay can use its own WAN address while retaining the final server destination.
- A pure per-hop forwarding decision function that authenticates/decrypts one NLR1 layer, validates the decrypted previous-hop locator against the observed source, checks the local receiver locator, rejects replay, and re-wraps the opaque inner envelope for the configured next hop.\n- An NLE2 endpoint envelope that encrypts the complete original IP packet (including both IP addresses) to the destination router and signs the ciphertext with the origin Ed25519 identity key; relays must carry it opaque inside NLR1.
- Fail-closed handling when destination metadata is absent or truncated.
- Narrow nftables TPROXY rules for the configured UDP port and dedicated fwmark policy-routing tables.
- Teardown removes only the dedicated NLS nftables table and matching policy-routing entries.

## Not yet complete

This module is not yet called by `NLSDaemon`. The daemon still uses NLE1, and neither NLR1 nor the new NLE2 endpoint envelope is wired into its session/data path. Do not enable these kernel rules as a claim of protocol compliance. Before runtime activation, the next implementation step must add authenticated per-hop session/key selection, source-locator validation against the actual ingress source, replay-window enforcement for NLR1, final-destination route selection, integration of the NLE2 endpoint envelope with Router-CA identity lookup and replay state, server delivery, and return-path handling.

## Operator safety

- Run only in a lab or on a dedicated router with console access.
- The rules intercept UDP to the configured NLS port; use a dedicated port and dedicated table.
- Configure the network route so packets continue to the next authorized relay while retaining the final server destination.
- Verify with IPv6 WAN captures on every hop. Passing unit tests does not prove correct transit routing or metadata confidentiality.
