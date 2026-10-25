# NLS Configuration

## Data plane (NLD2)

NLD2 is the active SourceToken data-plane record. Each packet uses the directional
AES-256-GCM key and 4-byte IV prefix derived by the NLH2 handshake. The fixed
header contains magic/version, a configured metadata mode, and a 64-bit counter.
The complete clear header is authenticated as AEAD associated data. The encrypted
plaintext is the assigned message type followed by the complete inner IP packet.
The legacy counter-first payload and legacy NLE2 data format are rejected without
fallback.

Configure the same `metadata_mode` on both session endpoints:

- `source-destination` (default): no inner destination metadata is visible.
- `source-only`: exposes a 17-byte destination descriptor (IP version plus
  16-byte address slot); its value is authenticated and checked against the
  decrypted inner destination.

    nls:
      enabled: false
      metadata_mode: source-destination
      replay_window: 128
      enforce_inner_source_prefix: true
      tun:
        enabled: true
        name: nls0
        mtu: 1184

The replay window must be between 1 and 4096 packets and is committed only
after successful AEAD authentication. A directional key must be rekeyed before
2^32 packets have been sent under that key. A mismatch in peer metadata-mode
configuration fails closed; do not enable a legacy fallback.

The conservative worst-case NLD2 overhead is 96 bytes: IPv6 outer header (40),
UDP header (8), common NLD2 header (14), mode-1 visible destination (17),
encrypted message type (1), and AES-GCM tag (16). A 1184-byte TUN MTU therefore
fits the IPv6 minimum outer path MTU of 1280 bytes. For a WAN path with MTU 1500,
a larger TUN MTU may be possible, but it must remain at or below the measured
path MTU minus 96 bytes. The implementation rejects a configured TUN MTU above
the safe transport MTU when a bind interface is configured.

Inner source addresses are checked against the peer's verified Router Directory
Record (RDR) prefixes by default. Inner destination addresses are checked
against the local router's verified RDR prefixes. Rejected packets are dropped
with stable reason codes and without logging packet contents or key material.

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
