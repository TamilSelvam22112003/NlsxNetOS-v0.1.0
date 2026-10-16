# NLS Configuration

## Data plane (NLE2)

NLE2 is the only active NLS data-plane format. Each packet uses the directional
AES-256-GCM key and 4-byte IV prefix derived by the NLH2 handshake. The 32-byte
NLE2 header is authenticated as AAD and contains only magic/version, reserved
flags, session ID, and a 64-bit sequence number. Inner IP addresses and payload
are encrypted. No per-packet RSA wrapping is used.

    nls:
      replay_window: 128
      enforce_inner_source_prefix: true
      tun:
        enabled: true
        name: nls0
        mtu: 1400

The replay window must be between 1 and 4096 packets and is committed only
after successful AEAD authentication. A directional key must be rekeyed before
2^32 packets have been sent under that key.

The maximum safe TUN MTU is the WAN MTU minus 96 bytes: IPv6 outer header (40),
UDP header (8), NLE2 header (32), and AES-GCM tag (16). A 1400-byte TUN MTU
therefore requires a WAN MTU of at least 1496 bytes; use a smaller TUN MTU on
lower-MTU links. The implementation rejects a configured TUN MTU above the
computed limit.

Inner source addresses are checked against the peer's verified Router Directory
Record (RDR) prefixes by default. Inner destination addresses are checked
against the local router's verified RDR prefixes. Rejected packets are dropped
with stable reason codes and without logging packet contents or key material.

NAT traversal is **NOT VERIFIED**.
