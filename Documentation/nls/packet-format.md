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

## Data envelope (active NLD2 SourceToken path)

Common header:

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | `NLD2` magic |
| 4 | 1 | version = 2 |
| 5 | 1 | mode = 1 (Mode A, `source-only`) or 2 (Mode B, `source-destination`) |
| 6 | 8 | counter, unsigned big-endian |
| 14 | 17, mode 1 only | visible destination: IP version byte plus 16-byte address slot |
| after header | variable | AES-256-GCM ciphertext plus 16-byte tag |

The common header is 14 bytes. Mode 1 has a 31-byte clear header; mode 2 has a 14-byte clear header. The AEAD associated data is outer IPv6 source (16 bytes) || outer IPv6 destination (16 bytes) || the entire clear header. The encrypted plaintext is message_type (1 byte, currently 0 only) || complete original IP packet. Nonce = directional 4-byte IV prefix || 8-byte counter. Separate directional keys are used; counter wrap is forbidden.

In Mode A (mode 1), the visible destination field is authenticated and must match the decrypted inner packet's destination. IPv4 is encoded as version 4 plus 12 zero bytes and the 4-byte destination; IPv6 is version 6 plus the 16-byte destination. In Mode B (mode 2), no inner destination field is present and both inner source and destination are encrypted. Both modes still expose the outer SourceToken, destination-router WAN address, UDP ports, packet sizes, timing, and traffic patterns.

The total outer overhead is 96 bytes in mode 1 and 79 bytes in mode 2 (IPv6 + UDP + clear header + encrypted message-type byte + AEAD tag). Mode mismatch, malformed framing, invalid AEAD, and legacy formats are rejected without fallback. `nls/source_token.py` implements NLD2 seal/open; the active daemon uses SourceToken lookup, session keys, and replay-window checks. The legacy NLE2 helper definitions are not a data-plane fallback.

