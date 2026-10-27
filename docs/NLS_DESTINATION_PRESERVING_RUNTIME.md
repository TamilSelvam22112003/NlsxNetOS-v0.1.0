# Destination-preserving NLS runtime

Status: **feature-gated runtime implementation; not yet accepted as production-ready**.

The intended data path keeps the final server IP as the outer IPv6 destination at every relay. Each emitting relay sets the outer source to its own WAN IPv6 address. The original IP packet is encrypted to the destination router in NLE2; each relay wraps that opaque endpoint envelope in a hop-specific NLR1 AEAD envelope. The receiving relay authenticates its own hop layer, checks the encrypted previous-hop locator against the observed outer source, enforces replay protection, and either re-wraps the opaque endpoint envelope or delivers it at the destination router.

The outer IPv6 source and final destination remain visible by design. The original client IP, original server IP, and application packet are encrypted inside NLE2. NLR1 protects the previous-hop locator and the endpoint envelope in transit. Timing, packet lengths, traffic volume, direction, and the final server address are not concealed.

## Implemented in this branch

- NLE2 endpoint envelope: RSA-OAEP-wrapped AES-256-GCM packet encryption plus Ed25519 origin signature; original IP header/destination are inside ciphertext.
- NLR1 per-hop AEAD envelope and forwarding decision function, including previous-hop source-locator validation, local next-hop binding, and replay-window checks.
- Feature-gated daemon path for NLE2 creation, NLR1 wrapping, transparent receive, relay re-wrapping, and opaque forwarding of NLE2 to the server endpoint agent. The router does not decrypt the application packet at the final hop.
- Linux transparent UDP socket with original destination/ingress-interface extraction and source-selected sends.
- Dedicated nftables IPv6 TPROXY interception and separate policy-routing tables for marked relay output.
- Startup validation and cleanup for dedicated firewall/routing state.
- Server-side `nls-endpoint-agent` CLI that verifies an active Router-CA origin identity/signature, decrypts NLE2 with the server private key, enforces replay windows, and injects the original IP packet into a server TUN interface.
- Unit tests for envelope privacy/integrity, endpoint-agent trust/replay, hop source validation, transparent packet-info parsing, and config gating.

## Configuration contract

The new path is opt-in and intentionally rejects automatic direct-to-destination peer discovery. Each router must have explicit next-hop peers whose `allowed_prefixes` are the final destination prefixes reachable through those peers. The server endpoint's most-specific Router-CA entry must publish the server agent's RSA encryption public key; each router's explicit next-hop peer entry supplies the authenticated hop session and route. The destination router validates the NLE2 signature but forwards the envelope opaque; the server agent owns the decryption key.

Example shape (replace documentation addresses and placeholder keys with lab Router-CA values):

```yaml
nls:
  enabled: true
  forwarding_mode: destination_preserving
  auto_router_ca: false
  listen_address: "2001:db8:1::1"  # exact advertised local WAN address
  listen_port: 4789
  bind_interface: "eth0"
  tun:
    enabled: true
    name: "nls0"
    mtu: 1280
  peers:
    - id: "router-2"
      endpoint: "[2001:db8:2::1]:4789"
      router_ca_id: 2
      public_key: "<Router-CA Ed25519 public key>"
      encryption_public_key: "<Router-CA RSA encryption public key>"
      allowed_prefixes:
        - "2001:db8:ffff::/64"  # final server prefix reached through router-2
```

On each router, configure the prefix-to-next-hop mapping for that router's next hop; the mappings differ along the path. The marked output routing table must route each final destination prefix through the configured next-hop WAN address. The daemon does not invent a relay chain or change OSPF routes automatically. This mode currently supports global IPv6 next-hop addresses and one configured WAN interface.

On the server host, register the server endpoint agent's own Ed25519 identity and RSA encryption public key in Router-CA with the server IP as the most-specific prefix, then run the endpoint agent (example):

```bash
sudo nls-endpoint-agent --listen-address 2001:db8:ffff::80 --listen-port 4789 \
  --gateway 2001:db8:ffff::1 --interface eth0 \
  --remote-prefix 2001:db8:abcd::/64 \
  --private-key /var/lib/nlsxnetos/identity/rsa-encryption.pem \
  --identity-key /var/lib/nlsxnetos/identity/ed25519.key --tun nls-endpoint0 --mtu 1280
```

The endpoint agent receives NLE2, verifies the origin against an active Router-CA identity, decrypts with the server's private key, and injects the original IPv6 packet into the server's TUN interface. For replies, it wraps the server's response packet in NLE2 addressed to the registered destination-router encryption key and sends it to the original client destination via the local NLS router; the router must then wrap it in NLR1 and forward it. This return path is represented in draft code, but has not yet been proven with end-to-end integration tests or WAN captures. The current per-packet RSA-OAEP wrapping does not provide forward secrecy and is a temporary prototype, not the final key-establishment design.


## Acceptance still required

The router and server-agent request/response paths are wired behind `forwarding_mode: destination_preserving`, but they have **not** been validated in a live multi-router lab. Do not enable this draft mode on a production router until all of these pass:

1. Run compileall, unit/security tests, package/fresh-install CI on the exact head commit.
2. Verify the kernel policy routes with `ip -6 rule`, `ip -6 route show table 100`, and `ip -6 route show table 200`.
3. Capture WAN traffic on R1, R2, R3, and the destination router. Confirm every NLR1 UDP packet keeps the final server IP as destination and changes source to the emitting relay's WAN address.
4. Confirm original client/server IP canaries and application payload do not appear in NLR1 cleartext.
5. Test source spoofing, wrong hop token/key, replay, wrong local receiver locator, unknown/revoked Router-CA identity, MTU/IPv6-fragment reassembly, missing next-hop session, and the server-agent return path.
6. Confirm failure cleanup removes only the dedicated NLS TPROXY table and NLS route table, without disturbing operator routes.

The branch contains draft request and response paths. It must not be described as fully working until exact-head CI passes, bidirectional delivery is proven in a live lab, and WAN packet-capture gates pass.

## Attachment-specific workflow: implementation status and hard gates

The attached NLS workflow asks for (a) per-hop source-locator metadata encrypted for the next authorized relay, (b) original client/server IP headers and transport/application data encrypted to the destination security endpoint, (c) per-hop validation and source rewrite, (d) Router-CA/vIP-based trust, and (e) actual routing integration.

Current implementation status:
- The draft daemon creates an NLE2 envelope using RSA-OAEP-wrapped AES-256-GCM and signs it with Ed25519; NLR1 protects the previous-hop locator and wraps the NLE2 bytes.
- The existing NLSH router handshake uses ephemeral X25519 and HKDF-SHA-256 for router hop sessions. This is separate from NLE2 endpoint key establishment. NLE2 still wraps a fresh AES key per packet with the endpoint's RSA key and does not provide forward secrecy.
- NLSH's private vIP value is a ULA IPv6-format identifier, not a routable encrypted source field and not a change to the IP source header.
- The feature path uses Linux transparent sockets/TPROXY and deterministic prefix-to-next-hop routes. It does not patch FRR's OSPF/BGP/RIP protocol internals, and OSPF must not be described as rewriting data-packet source addresses.
- Relay outer destination is deliberately preserved as the final server IP. This differs from classic next-hop-addressed onion routing: the kernel routing path must deliver the final-destination packet to the local NLS process on each intermediate relay, otherwise ordinary IP forwarding will bypass the daemon. This behavior requires live validation on every platform/topology.

Acceptance rule: passing Python tests, CodeQL, package and emulated four-/ten-router jobs is necessary but not sufficient. Release acceptance also requires WAN captures from every relay proving that the outer destination remains the final server IP, the outer source changes to the transmitting relay, the next-hop source locator is recoverable only after that hop's AEAD key is used, and endpoint-address/payload canaries are absent from all cleartext framing. The endpoint request and response directions, MTU/ICMPv6 PTB, fragments, daemon restart/rekey, revoked identities and failure cleanup must be demonstrated in a live lab. Do not remove the draft gate before these proofs.

## Return-path correction (2026-10-27)

The server endpoint agent emits its response envelope toward the original client IPv6 destination. The first client-side router therefore receives the NLE2 datagram with the *client address* as its kernel-observed outer destination, not with the router's own WAN address. The NLS daemon validates that this is a unicast IPv6 final destination, validates the endpoint agent's registered source identity/source prefix and direct-LAN ingress, and then wraps the NLE2 bytes in the next-hop NLR1 session. The final destination remains the client address on each outbound relay datagram.

The port-scoped TPROXY rule intentionally sees both WAN relay packets and LAN-originated endpoint-agent response packets. It must not be widened beyond the configured NLS UDP port. Source-port, Router-CA, source-prefix, interface and session validation remain fail-closed. A live lab must prove this return direction, because unit tests cannot validate Linux route selection, transparent socket semantics, or the WAN packet capture.

## Forward-secret endpoint-session integration update (2026-10-27)

This section supersedes the earlier NLE2-only description above for the feature-gated destination-preserving path.

- **NLEH** performs authenticated ephemeral X25519 key agreement. Router-CA-pinned Ed25519 identities sign the handshake transcript; HKDF-SHA-256 derives directional traffic keys.
- **NLE3** protects the complete original IPv6 packet with AEAD under the negotiated endpoint-session key. The NLE3 framing exposes only the opaque session ID, sequence, nonce, length, and ciphertext; the inner source/destination IPv6 headers and transport/application data are encrypted.
- **NLR1** remains the per-hop AEAD envelope. A relay opens only its own NLR1 layer, checks the previous-hop locator against the observed outer source, and wraps the opaque NLEH/NLE3 bytes for the next hop.
- The router can terminate an NLEH session when the Router-CA identity belongs to that router, or forward an NLEH INIT to a registered server endpoint agent. Agent responses are correlated with the original authenticated hop session and returned through that hop. Endpoint-agent-originated handshakes can be routed back to the registered endpoint agent without exposing its private ephemeral key to the router.
- The server endpoint agent now has NLEH/NLE3 receive and transmit paths. The older NLE2 processor remains only as a legacy helper; the destination-preserving router path rejects NLE2 rather than silently downgrading to RSA-wrapped per-packet keys.

The endpoint session primitive has unit coverage for matching directional keys, X25519/HKDF agreement, identity/transcript binding, replay rejection, tampering, destination binding, and inner-address/payload confidentiality. The newly integrated router/endpoint-agent control-flow still requires exact-head CI and a live multi-router lab. Do not interpret the protocol primitives' tests as proof that transparent routing or the complete return path is production-ready.
