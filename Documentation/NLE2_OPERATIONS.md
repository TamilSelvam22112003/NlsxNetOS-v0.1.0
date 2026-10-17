# NLE2 Session Lifecycle and Operations

## Rekey policy

The default per-direction key limit is 2^32 packets or one hour, whichever
reaches its 90% trigger first. The configurable fields are:

- `rekey_packet_limit`: default 4294967296; reduced values are supported for tests.
- `rekey_seconds`: default 3600.
- `rekey_overlap_seconds`: default 5.

A rekey uses the normal NLH2 handshake. The replacement session becomes the
preferred transmit session; the previous session remains receive-capable during
the overlap. Simultaneous rekey attempts use deterministic router-ID ordering:
the lexicographically lower router ID's initiated handshake wins. Old sessions
are removed at overlap expiry and their mutable key buffers are overwritten.
If a session reaches its hard packet limit before the replacement is ready,
the bounded pending-packet queue holds up to 64 packets while the handshake
completes; the queue remains bounded and can drop the oldest packet on overflow.

## CA freshness and revocation

The runtime checks the verified directory cache at the configured Router-CA
heartbeat interval (default 30 seconds), with a one-second event-loop polling
bound. A session is removed when directory freshness expires, either router's
RDR becomes inactive, the peer certificate is revoked, a stable RDR field
changes, or a record sequence rolls back. The active-session check uses the
directory's actual expiry timestamp; a nonzero stale-grace setting does not
allow an established session to outlive CA freshness. The default stale grace
is zero.

## Status and doctor

The daemon atomically publishes a JSON snapshot at
`/run/nlsxnetos/nls-status.json`. Tests and supervised instances can override
the path with `NLSXNETOS_NLS_STATUS_PATH`. The `nlsxnetos nls status` command
shows session peer/state, bytes and packets in both directions, rekey age,
directory freshness, aggregate counters, and per-reason-code counters.

The `nlsxnetos doctor` command checks whether the current process has
CAP_NET_ADMIN for vIP operations, reports verified-directory freshness, and
tests TCP reachability to the configured Router-CA endpoint in CA trust mode.
A failing check is not silently treated as healthy when NLS is enabled.

## Key zeroization limits

Session send/receive keys are stored in mutable bytearrays and overwritten
when a session closes, is revoked, loses CA freshness, or leaves the overlap.
This is best-effort Python-level zeroization, not a hard guarantee: immutable
bytes created by cryptographic APIs, transient interpreter copies, OpenSSL
internal buffers, allocator reuse, core dumps, and swap may retain material.
The implementation does not claim guaranteed erasure of those copies. Deploy
with core dumps disabled, restricted process access, encrypted swap where
applicable, and appropriate host hardening.

NAT traversal is **NOT VERIFIED**.
