# NLS Metadata Confidentiality Profile (Design Gate)

**Status: PROPOSED — NOT IMPLEMENTED.** This document records the target security property and implementation contract. It does not claim that current NlsxNetOS releases provide multi-hop metadata confidentiality. Do not enable this profile until the protocol, Core, NetOS, installer, and packet-capture acceptance gates pass.

Related tracking:
- NetOS implementation: https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/issues/67
- Core protocol contract: https://github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.0/issues/15

## 1. Security objective

An on-path Internet observer at a link between NLS relays may learn the current hop's routable locator pair and the unavoidable traffic pattern, but must not recover the original client/server IP addresses, inner transport ports, application payload, endpoint certificates, stable endpoint identities, or prior-hop locators from the packet headers or NLS framing.

This is a confidentiality objective against a passive observer. It does not by itself hide timing, direction, packet lengths, or total traffic volume, and does not protect against a compromised relay or endpoint.

## 2. Correct interpretation of outer addresses

The actual IPv6 source and destination fields are not encryptable in place: ordinary IP routers need a routable destination to forward the packet. NLS MUST use routable hop locators:

- outer IPv6 source = the current NLS relay's WAN locator;
- outer IPv6 destination = the next NLS relay's WAN locator;
- UDP ports = the configured NLS transport ports for that hop;
- clear NLS framing = fixed/versioned framing and only a per-hop opaque routing token plus fields required for safe processing.

The outer source address is visible to an observer. Its privacy property is that it identifies only the current relay, not the original client. An encrypted copy of a previous hop's locator, if needed, belongs inside the authenticated envelope, never in a field that the kernel/IP network must parse.

## 3. Required layered packet model

A conforming implementation uses nested, independently authenticated layers. It MUST NOT treat a single destination-router-encrypted packet as equivalent to onion routing or end-to-end protection.

### 3.1 End-to-end endpoint envelope

Before forwarding, the client endpoint creates an end-to-end envelope using an authenticated endpoint key agreement and directional traffic keys derived with HKDF-SHA-256. Use AEAD (AES-256-GCM or a separately versioned, reviewed alternative), unique nonces, explicit sequence numbers, and authenticated context.

The endpoint envelope contains the original client/server IP packet (including original IP and transport headers) and is opaque to intermediate relays. The endpoint key agreement must authenticate the intended server endpoint or its explicitly designated endpoint agent. A router's public key alone is not a server identity.

### 3.2 Destination delivery envelope

Because the destination router cannot route using an encrypted original destination address, the destination-side envelope MUST carry a delivery locator authenticated/encrypted for the destination router. The delivery locator is a destination-LAN/endpoint-agent locator, not the original client's address. The destination router removes only this layer and delivers the opaque end-to-end envelope to the configured server endpoint agent. That agent authenticates/decrypts the endpoint envelope and injects the recovered original IP packet into the server-side stack.

If the design instead terminates encryption at the destination router and injects plaintext IP there, it provides router-to-router confidentiality only; it MUST NOT be described as client-to-server end-to-end encryption.

### 3.3 Per-hop relay layers

For each relay hop, the sender wraps the next envelope in a per-hop AEAD layer using a session established with that relay. Each relay:

1. validates the authenticated hop/session context and replay window;
2. decrypts only the layer addressed to itself;
3. obtains the next routable relay locator and next opaque envelope;
4. forwards using its own WAN locator as outer source and the next relay's WAN locator as outer destination;
5. never logs or exports plaintext inner endpoint identities.

Hop keys MUST be independent from end-to-end endpoint keys. A relay compromise may reveal that relay's local hop state and traffic pattern, but must not reveal the endpoint envelope plaintext or keys.

## 4. Key establishment and trust

- Use authenticated X25519 ephemeral key agreement, transcript-bound HKDF-SHA-256, and directional keys; do not RSA-wrap a newly generated AES key on every data packet.
- Router identity/certificate validation is separate from server endpoint identity validation.
- Each peer/relay identity, endpoint locator, key purpose, validity period, revocation status, and permitted role must be explicit in authenticated policy.
- Key material is scoped to a session and direction; nonce uniqueness is mandatory for every AEAD key.
- Rekeying, overlapping sessions, revocation, endpoint changes, restart recovery, and replay-window persistence/expiry must have specified behavior.
- Unknown versions, missing trust, invalid locator bindings, expired/revoked keys, and failed authentication MUST fail closed. No silent fallback to legacy single-hop mode is allowed when the privacy profile is requested.

## 5. Cleartext field budget

The Internet-visible per-hop packet may contain only:

- routable outer IPv6 source/destination for that hop;
- UDP source/destination ports;
- protocol version and bounded length/framing fields;
- an opaque, hop-scoped session/routing token required to select the correct hop state;
- ciphertext and authentication tag.

The following MUST NOT appear in cleartext NLS framing on an untrusted hop: original client/server IP addresses, inner source/destination ports, original packet headers, endpoint certificates/public keys, stable client/server identifiers, prior-hop locator history, or application payload.

Opaque tokens should be rotated/scoped where feasible to reduce cross-hop and cross-session linkability. Any intentionally visible field must be listed in a versioned field-leakage table.

## 6. Traffic analysis boundary

Encryption does not inherently conceal packet timing, direction, sizes, burst structure, or total volume. A separate optional traffic-analysis-resistance profile may add padding, batching, shaping, or cover traffic. It must have explicit bandwidth, latency, MTU, and operational trade-offs and must not be implied by the base confidentiality profile.

## 7. Implementation and deployment gates

The profile is not complete until all of the following pass:

1. Freeze the normative wire format and state machine in the shared spec before implementation.
2. Implement matching packet codecs, hop state, end-to-end endpoint agent, trust checks, replay protection, rekey, and failure behavior in NexOS Core and NlsxNetOS.
3. Update installer/configuration and CLI so a multi-hop route and endpoint trust can be provisioned reproducibly; show an explicit status that distinguishes legacy transport from the metadata-confidentiality profile.
4. Ensure enabling the profile fails if any required relay, trust, key, route, endpoint agent, or firewall prerequisite is missing.
5. Add unit tests for malformed fields, tampering, wrong peer/port/local destination, replay, nonce uniqueness, expiry, rekey overlap, endpoint changes, and downgrade attempts.
6. Add a multi-router IPv6 integration lab with at least three relays and a separate server endpoint agent. Test bidirectional payloads, restart/recovery, MTU/fragmentation, and ICMPv6 Packet Too Big behavior.
7. Capture actual decodable NLS packets on every WAN link. Automated assertions must show that original endpoint IPs, inner ports, endpoint certificates, stable identifiers, and unique payload canaries do not occur in the untrusted-hop IP/UDP/NLS headers or cleartext framing. Retain the raw PCAP, decoder output, expected packet count, and test manifest.
8. Verify OSPFv3/RIB/FIB invariance: derived vIPs and original endpoint identities must not be installed or advertised as WAN locators. Outer hop locators must be valid, routable addresses.
9. Test clean installation and documented configuration on each supported Ubuntu release. If the profile is not configured, clearly report that the privacy property is not active; never claim protection based only on successful AES-GCM round trips.

## 8. Required capture assertions

For each untrusted WAN capture, the analyzer must parse the actual NLS transport (not accept a non-NLS UDP packet or a byte-substring check as proof). It must verify:

- all expected NLS packet types and minimum packet count are present;
- outer addresses are exactly the configured current-hop/next-hop locators;
- original client/server IPs, inner ports, certificates, stable IDs, and payload canaries are absent from all visible headers/framing;
- only explicitly approved cleartext fields appear before ciphertext;
- mutations to ciphertext, tag, session token, hop locator, or sequence are rejected;
- replayed valid packets are rejected;
- the destination endpoint agent can recover the original packet only with its end-to-end key;
- relays without the end-to-end key cannot decrypt the endpoint envelope.

A PCAP with no decodable NLS packet is a failed/inconclusive test, never a pass.

## 9. Existing implementation boundary

The current `nls/encapsulation.py` NLE1 format is a single destination-router encapsulation. Its visible header includes a destination field, router identity, session ID, sequence, timestamp, and wrapped-key length, and it encrypts the original IP packet with AES-GCM. This does not establish the layered multi-hop/end-to-end properties above. The current format must not be silently reinterpreted; incompatible changes require an explicit new wire-format version and compatibility policy.


## 10. Normative source-address handling clarification

The NLS source-address requirement is **hop-scoped source-metadata confidentiality**: the relay packages the preceding/current relay's source-locator metadata inside an authenticated encrypted hop envelope addressed to the next authorized relay. The next relay decrypts that envelope with the hop/session key established for it (the next relay's public key may authenticate or establish that session; do not use unauthenticated raw public-key encryption as a substitute for an AEAD session), validates the locator and policy, and uses its own routable WAN locator as the source of the newly emitted outer IPv6 packet when forwarding onward. The forwarding relay may retain the authenticated prior-hop locator only for the scoped operation that requires it; it must not expose it in clear NLS framing or logs.

**Wire-level limitation:** this encrypted source-locator field is metadata carried inside the envelope; it does not encrypt or replace the actual outer IPv6 Source Address field. The actual outer IPv6 source remains the current relay's routable WAN address and is visible to the next relay and to on-path observers. Ordinary Internet IPv6 forwarding cannot deliver a packet to a next hop if the routable outer destination is encrypted in place. If the requirement is to hide even the current relay's actual WAN source address from passive Internet observers, that requires an additional outer tunnel/cover endpoint; it cannot be achieved by encrypting the source field while keeping the same ordinary IPv6 packet routable.

The normative inner hop plaintext must therefore include an authenticated previous_hop_source_locator (address family + normalized address) in addition to the encrypted next_hop_locator and opaque inner envelope. The Core and NetOS codecs and cross-repository test vectors must agree on this field before the profile is considered implementable. Tests must assert that this locator appears only inside ciphertext, that the receiving relay recovers it only with its authorized hop key, and that the forwarded outer source is the forwarding relay's configured WAN locator.
