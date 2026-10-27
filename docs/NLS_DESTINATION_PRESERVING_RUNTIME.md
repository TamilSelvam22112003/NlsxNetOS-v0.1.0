# Destination-preserving NLS runtime

Status: **feature-gated runtime implementation; not yet accepted as production-ready**.

The intended data path keeps the final server IP as the outer IPv6 destination at every relay. Each emitting relay sets the outer source to its own WAN IPv6 address. The original IP packet is encrypted to the destination router in NLE2; each relay wraps that opaque endpoint envelope in a hop-specific NLR1 AEAD envelope. The receiving relay authenticates its own hop layer, checks the encrypted previous-hop locator against the observed outer source, enforces replay protection, and either re-wraps the opaque endpoint envelope or delivers it at the destination router.

The outer IPv6 source and final destination remain visible by design. The original client IP, original server IP, and application packet are encrypted inside NLE2. NLR1 protects the previous-hop locator and the endpoint envelope in transit. Timing, packet lengths, traffic volume, direction, and the final server address are not concealed.

## Implemented in this branch

- NLE2 endpoint envelope: RSA-OAEP-wrapped AES-256-GCM packet encryption plus Ed25519 origin signature; original IP header/destination are inside ciphertext.
- NLR1 per-hop AEAD envelope and forwarding decision function, including previous-hop source-locator validation, local next-hop binding, and replay-window checks.
- Feature-gated daemon path for NLE2 creation, NLR1 wrapping, transparent receive, relay re-wrapping, and destination-router endpoint decryption.
- Linux transparent UDP socket with original destination/ingress-interface extraction and source-selected sends.
- Dedicated nftables IPv6 TPROXY interception and separate policy-routing tables for marked relay output.
- Startup validation and cleanup for dedicated firewall/routing state.
- Unit tests for envelope privacy/integrity, hop source validation, replay rejection, transparent packet-info parsing, and config gating.

## Configuration contract

The new path is opt-in and intentionally rejects automatic direct-to-destination peer discovery. Each router must have explicit next-hop peers whose `allowed_prefixes` are the final destination prefixes reachable through those peers. The endpoint router's Router-CA entry supplies the end-to-end encryption key; the next-hop peer entry supplies the authenticated hop session and route.

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
    mtu: 1200
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

## Acceptance still required

Although the daemon path is now wired behind `forwarding_mode: destination_preserving`, it has **not** been validated in a live multi-router lab in this task. Do not enable it on a production router until all of these pass:

1. Run compileall, unit/security tests, package/fresh-install CI on the exact head commit.
2. Verify the kernel policy routes with `ip -6 rule`, `ip -6 route show table 100`, and `ip -6 route show table 200`.
3. Capture WAN traffic on R1, R2, R3, and the destination router. Confirm every NLR1 UDP packet keeps the final server IP as destination and changes source to the emitting relay's WAN address.
4. Confirm original client/server IP canaries and application payload do not appear in NLR1 cleartext.
5. Test source spoofing, wrong hop token/key, replay, wrong local receiver locator, unknown/revoked Router-CA identity, MTU/fragmentation, missing next-hop session, and return-path traffic.
6. Confirm failure cleanup removes only the dedicated NLS TPROXY table and NLS route table, without disturbing operator routes.

The branch contains the runtime integration, but it must not be described as fully working until the exact-head CI and WAN packet-capture gates pass.
