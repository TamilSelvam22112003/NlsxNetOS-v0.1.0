# NLS v1 packet format

**Status:** NLE2 implementation is present in nls/encapsulation.py on feat/nls-v1. This document describes the intended/implemented byte layout; end-to-end conformance must be confirmed by current branch-head tests.

## Handshake envelope
| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | NLH2 magic |
| 4 | 1 | version=1 |
| 5 | 1 | type=M1/M2/M3/M4 |
| 6 | 16 | session_id |
| 22 | 2 | envelope_length, u16 big-endian |
| 24 | variable | SEAL envelope |
Fixed prefix 24 bytes; length must exactly match datagram. Payload is deterministic CBOR. SEAL carries wrapped 32-byte AES key, random 12-byte nonce, ciphertext and 16-byte tag. AAD binds NLH2/version/type/session_id; sender signature is inside plaintext. OAEP and MGF1 use SHA-256 and fixed documented label policy.

## Data envelope
| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | NLE2 magic |
| 4 | 1 | version=2 |
| 5 | 1 | flags=0 |
| 6 | 2 | reserved=0 |
| 8 | 16 | session_id |
| 24 | 8 | seq, unsigned big-endian |
| 32 | variable | AES-256-GCM ciphertext plus final 16-byte tag |
Header exactly 32 bytes and is the complete AEAD AAD. No inner addresses, timestamp, explicit nonce, or wrapped key in header. Nonce=directional 4-byte IV prefix||8-byte sequence. Separate c2s/s2c keys; sequence wrap forbidden.
Outer IPv6/UDP/NLE2 header/session ID/sequence remain visible. Original inner IP header (including source/destination) and transport payload are encrypted. Fixed IPv6+UDP+header+tag overhead=40+8+32+16=96 bytes; TUN MTU <= effective WAN path MTU minus 96. Reject oversize packets. nls/encapsulation.py defines HEADER, seal_ip_packet, and open_ip_packet for NLE2 directional session-key protection. Session lookup, key lifecycle, and replay-window behavior are implemented across the session and replay modules and must be verified together by integration tests.