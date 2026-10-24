# NLS Configuration

## Data plane (NLD2)

The active daemon data path uses versioned NLD2 SourceToken records with AES-256-GCM and directional keys derived by the NLH2 handshake. Configure the same `metadata_mode` on both routers in a session:

- `source-destination` (default, wire mode 2): encrypts the complete inner IP packet, exposing neither inner endpoint address in the NLD2 header.
- `source-only` (wire mode 1): encrypts the complete inner IP packet but exposes the original inner destination in a 17-byte clear header field authenticated as AEAD associated data. The receiver verifies it matches the decrypted destination.

```yaml
nls:
  metadata_mode: source-destination
  replay_window: 128
  enforce_inner_source_prefix: true
  tun:
    enabled: true
    name: nls0
    mtu: 1280
```

A mode mismatch is rejected; there is no automatic fallback to the previous counter-first SourceToken format or legacy NLE2. Upgrade both routers together. An invalid mode value rejects configuration.

NLD2 uses a 14-byte common clear header: magic `NLD2` (4), version (1), mode (1), and counter (8). Source-only mode adds a 17-byte visible-destination field (IP version byte plus 16-byte address slot). The full clear header is AEAD associated data, along with the outer IPv6 source and destination. The encrypted plaintext begins with a one-byte message type followed by the complete inner IP packet. The 12-byte nonce is the directional 4-byte IV prefix concatenated with the 8-byte counter; counters must not wrap and are limited by the 2^32 rekey threshold.

The replay window must be between 1 and 4096 packets and is committed only after successful AEAD authentication. Invalid tags, mode mismatches, destination mismatches, and duplicate counters must not advance replay state.

The maximum safe TUN MTU is the WAN path MTU minus 79 bytes for source-destination mode, or minus 96 bytes for source-only mode. These values include the outer IPv6 header, UDP header, NLD2 header, optional visible destination, encrypted message-type byte, and AES-GCM tag. Use a smaller TUN MTU on lower-MTU links; the implementation rejects a configured TUN MTU above its calculated limit.

Inner source addresses are checked against the peer's verified Router Directory Record (RDR) prefixes by default. Inner destination addresses are checked against the local router's verified RDR prefixes. Rejected packets are dropped with stable reason codes and without logging packet contents or key material.

NAT traversal is **NOT VERIFIED**.

## Time and freshness bounds

The signed directory lookup has a maximum age of 30 seconds. An RDR with
issued_at 29 seconds in the past is accepted; one 31 seconds old is rejected.
There is zero tolerated future skew for issued_at (future-dated records fail
closed). valid_until must be in the future and no more than 30 seconds ahead.
The default handshake timeout remains 5 seconds. Handshake message timestamps
use max_clock_skew_seconds (default 120 seconds); this is distinct from the
stricter signed-directory freshness interval. Keep hosts synchronized with a
reliable time source and do not relax directory freshness to compensate for
clock drift.
