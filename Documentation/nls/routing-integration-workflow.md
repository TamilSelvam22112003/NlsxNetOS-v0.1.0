# NLS routing and packet-forwarding workflow

**Status:** Architecture/workflow reference for the experimental NLS v1 implementation. This document describes the specified endpoint-tunnel model; it does not claim per-hop re-encryption by every transit router.

## 1. Design boundary

NLS is a security/data-plane mechanism integrated with ordinary Linux routing. OSPFv2/OSPFv3 and BGP continue to discover reachability and populate routing state. NLS consumes that state to select an authorized destination router and transport protected inner packets. An OSPF adjacency or BGP session is not, by itself, an authenticated NLS session.

The current protocol specification defines Router S (source/ingress) and Router D (destination/egress) as NLS endpoints. Routers between S and D forward the outer IPv6/UDP packet using ordinary routing; they do not decrypt and re-encrypt the NLS payload at each transit hop. A future hop-by-hop design would require a separate protocol amendment, wire format, and threat-model review.

## 2. Boot and route discovery

1. Linux brings up interfaces and configured IPv4/IPv6 addresses.
2. FRRouting starts the configured OSPF and/or BGP processes.
3. Routing adjacencies form and route state converges normally.
4. NLS loads its persistent router identity, CA trust anchors, signed directory state, policy, and operator-configured NLS routes.
5. The router validates local identity and directory freshness. Missing, invalid, expired, or revoked trust material fails closed for NLS session establishment.
6. NLS does not create forwarding routes merely because a Router-CA record advertises a peer or prefix. Routes into the NLS TUN are operator-configured and bind a prefix to a router ID.

## 3. Peer lookup and handshake

Assume source router S must send a client packet to destination router D.

1. S looks up the configured NLS route and determines D's router ID.
2. S obtains a fresh signed Router Directory Record (RDR) for D. The record supplies the authenticated identity, certificate/key material, status, prefixes, and ordered WAN endpoints.
3. S validates the RDR signature against the out-of-band-pinned Router-CA directory key, nonce binding, freshness, record sequence, certificate status, and address policy.
4. S creates a fresh session ID and a short-lived vIP according to the authoritative hybrid NLH2 specification. The vIP is a bootstrap source identifier/address, not proof of identity by itself.
5. S sends M1 to D's reachable WAN endpoint, with the outer source set to the vIP. The handshake payload is sealed to D's RSA encryption key from the verified directory, signed by S, and bound to the message type, version, and session ID.
6. D validates message framing and performs a bounded early check against its cached signed directory. It does not create long-lived trusted state merely because M1 arrived.
7. D sends M2 to the bootstrap vIP, sealed to S's directory-verified RSA key and signed by D.
8. S performs a fresh Router-CA lookup for D and compares M2's identity, certificate, keys, endpoint, gateways, and proposals with the signed RDR and CA policy. A mismatch aborts.
9. S sends M3, including its signed identity record and ephemeral X25519 public key, sealed using D's CA-verified encryption key.
10. D performs a fresh lookup for S and verifies M3 and M1 against the signed RDR. A mismatch aborts.
11. The peers derive directional session keys using X25519 and HKDF-SHA256, verify key confirmation, and complete M4.
12. After successful confirmation, both sides switch to the verified real WAN endpoints. S removes the temporary vIP; later packets using that vIP as an outer source are rejected.
13. Only after successful completion is the data session installed.

Handshake state must be bounded. Malformed or unauthenticated M1 traffic must not reserve a router identity or block a legitimate peer. Failures are dropped on the wire and recorded using stable reason codes without secret material.

## 4. Data-plane packet forwarding

The specified NLE2 data packet contains a 32-byte header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | NLE2 magic |
| 4 | 1 | Version (2) |
| 5 | 1 | Flags (0) |
| 6 | 2 | Reserved (0) |
| 8 | 16 | Session ID |
| 24 | 8 | Directional sequence number, unsigned big-endian |
| 32 | Variable | AES-256-GCM ciphertext followed by a 16-byte tag |

The header is AEAD associated data. The nonce is the directional 4-byte IV prefix concatenated with the 8-byte sequence number. Independent keys are used in each direction. No per-packet RSA operation is part of NLE2.

1. A client packet arrives on S's client LAN.
2. S performs a route lookup and checks the operator-configured NLS policy.
3. S verifies that a live, authorized session exists to D. If not, it initiates the handshake or queues traffic within a bounded policy.
4. S encrypts the complete original IP packet, including the original source and destination addresses, using the session's directional AEAD key.
5. S sends the NLE2 envelope over UDP/IPv6 to D's verified WAN endpoint.
6. Transit routers use ordinary IPv6 routing to forward the outer packet. The outer destination and transport metadata required for delivery remain visible; the inner IP header and payload are encrypted.
7. D resolves the session ID, validates header and length, verifies AEAD integrity, and checks the replay window. Replay state advances only after authentication succeeds.
8. D checks that the decrypted inner source is within S's authorized RDR prefixes when enforce_inner_source_prefix is enabled.
9. D writes/forwards the authenticated inner packet through the configured Linux routing path to the destination server LAN.
10. Return traffic follows the explicitly configured reverse NLS route and the corresponding authenticated directional session or reverse session. Successful forward delivery alone does not guarantee return-path configuration.

## 5. OSPF/BGP coexistence

- OSPF Hello, database exchange, link-state updates, acknowledgements, and OSPFv3 control traffic must remain processable by FRRouting.
- BGP OPEN, KEEPALIVE, UPDATE, and NOTIFICATION messages must remain processable by FRRouting.
- Routing changes can trigger session establishment, invalidation, or next-hop reevaluation, but must not be mistaken for cryptographic authentication.
- ARP, IPv6 Neighbor Discovery, DHCP, ICMPv6 errors, and required control traffic must not be accidentally captured by the NLS data path.
- CA directory metadata may authorize a peer or prefix; it must not autonomously install routes.
- Compatibility is established only by integration tests that demonstrate routing adjacencies, route exchange, and NLS traffic delivery concurrently.

## 6. Security properties and limits

NLS aims to authenticate participating routers, protect the inner packet with AEAD, reject replayed or tampered data, and keep original inner IP metadata out of the visible outer packet. It does not conceal the outer destination endpoint from transit routers, and it does not provide anonymity against traffic analysis by itself. A router that is an NLS endpoint can inspect the inner packet after decryption. Transit-router compromise, endpoint compromise, CA compromise, route hijacking, and traffic analysis remain relevant threats.

Do not describe NLS as categorically superior to TLS or IPsec. Compare mechanisms only with a defined threat model and measured evidence.

## 7. MTU and failure handling

The specified IPv6 + UDP + NLE2 header + AEAD tag overhead is 96 bytes before any additional encapsulation. Derive the TUN MTU from the effective path MTU and test boundary packet sizes. Preserve ICMPv6 Packet Too Big handling; do not silently drop all ICMPv6. Reject oversize packets according to the documented policy.

Use structured reason codes for malformed packets, failed authentication, replay, stale CA data, invalid session, revoked peer, vIP-after-switch, and route/session mismatch. Never log private keys, session keys, decrypted payloads, or original source metadata unnecessarily.
