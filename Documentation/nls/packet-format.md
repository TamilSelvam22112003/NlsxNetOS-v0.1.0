# NLS v1 packet format

**Status:** NLH2 is the active handshake envelope. NLD2 is the active SourceToken data-plane framing on the implementation work branch; exact-head target-branch conformance is pending CI completion. The retired counter-first payload and legacy NLE2 session format are not accepted by the active daemon.

## Handshake envelope

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | NLH2 magic |
| 4 | 1 | version=1 |
| 5 | 1 | type=M1/M2/M3/M4 |
| 6 | 16 | session_id |
| 22 | 2 | envelope_length, u16 big-endian |
| 24 | variable | SEAL envelope |

Fixed prefix is 24 bytes; length must exactly match the datagram. Payload is deterministic CBOR. SEAL carries wrapped 32-byte AES key, random 12-byte nonce, ciphertext and 16-byte tag. AAD binds NLH2/version/type/session_id; sender signature is inside plaintext. OAEP and MGF1 use SHA-256 and the fixed documented label policy.

## Active data envelope: NLD2

NLD2 is a versioned record. The receiver rejects unknown magic, versions, mode values, malformed lengths, metadata-mode mismatches, and all legacy counter-first payloads; there is no fallback.

| Offset | Length | Field |
|---:|---:|---|
| 0 | 4 | magic `NLD2` |
| 4 | 1 | version=2 |
| 5 | 1 | metadata mode: 1=`source-only`, 2=`source-destination` |
| 6 | 8 | counter, unsigned big-endian |
| 14 | 0 or 17 | visible destination metadata; present only in mode 1 |
| variable | variable | AES-256-GCM ciphertext followed by 16-byte tag |

The encrypted plaintext is `message_type (1 byte) || complete inner IP packet`. Only message type 0 is assigned. In mode 1, the visible metadata is a 17-byte tuple: IP version byte plus a 16-byte address slot; IPv4 uses 12 zero bytes followed by the 4-byte destination. The receiver authenticates the visible destination and compares it with the decrypted inner destination. Mode 2 carries no visible inner destination.

The AEAD associated data is exactly:

`outer IPv6 source (16 bytes) || outer IPv6 destination (16 bytes) || complete clear NLD2 header`.

UDP ports are not included in the associated data. The nonce is the directional 4-byte IV prefix concatenated with the 8-byte counter. Counters begin at zero, increase strictly, and may not reach or exceed the 2^32 hard rekey limit. Replay state advances only after successful AEAD authentication.

Outer IPv6, UDP, NLD2 header, mode-1 visible metadata, and packet lengths remain observable. The inner IP header and payload are encrypted. NLD2 protects packet contents and selected metadata; it does not conceal packet timing, size, or outer forwarding endpoints.

## MTU

The worst-case NLD2 overhead is 96 bytes: IPv6 outer header (40), UDP (8), common NLD2 header (14), mode-1 metadata (17), encrypted message type (1), and GCM tag (16). Use a TUN MTU no greater than the effective WAN path MTU minus 96 bytes. Mode 2 uses 17 fewer bytes, but deployments should retain the conservative bound unless the configured mode is guaranteed at both peers. Reject oversize packets; do not silently fragment or alter acceptance thresholds.

## Legacy NLE2 note

`nls/encapsulation.py` retains NLE2 helpers for historical comparison and compatibility tests. NLE2 is not an active data-plane fallback and must not be emitted or accepted by the active SourceToken path.
