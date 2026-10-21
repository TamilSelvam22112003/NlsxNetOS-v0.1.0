# NLS vIP bootstrap and authenticated vIP/SourceToken table

## Lifecycle

The router-local NLS table is persisted at `/run/nlsxnetos/nls-lsdb.json` (configurable with `NLSXNETOS_NLS_LSDB`). It stores bootstrap vIPs separately from authenticated data-plane SourceTokens. It is NLS metadata; it does not write kernel routes or mutate FRR/OSPF LSDB state.

1. **Bootstrap reservation — `PENDING`.** The initiating router obtains a temporary IPv6 `/128` from `VIPManager`, assigns it to the configured WAN interface with `nodad`, binds its handshake socket to it, and records a `bootstrap_vip` row. The row includes the vIP, router identity, authoritative local `originalIP`, handshake/session ID, record sequence and expiry. It is explicitly `authenticated: false` and has no SourceToken. When a peer receives a valid and screened M1, it records the same source-vIP/session reservation locally before proceeding with the handshake.
2. **Authenticated session — `ESTABLISHED`.** Neither an incoming M1 nor a cached RDR alone is sufficient to publish reachability. After M4 signature/transcript/key-confirmation checks succeed and the bootstrap vIP has been retired, `_activate_session` publishes both directional SourceToken rows. The peer row maps the peer's `originalIP` and identity to `recv_token`; the local-direction row records this router's `originalIP` and `send_token`. Rows include session ID, Router-CA record sequence, authentication state and expiry.
3. **Make-before-break rekey — `OVERLAP` plus new `ESTABLISHED`.** The prior session's SourceToken rows remain available for the configured overlap interval to accept in-flight packets. The new established row is preferred by `resolve_original_ip()`. Old rows are removed by session ID after overlap expiry; a cleanup for an old session cannot delete a newer session's rows.
4. **Abort, timeout, revocation or shutdown.** Pending bootstrap rows are removed with the matching handshake/session ID. Established token rows are removed during session teardown. Expiry removes stale rows; the address recovery file tracks only NLS-owned temporary addresses for crash cleanup.

## Table APIs

- `publish_bootstrap_vip(...)`: reserves an unauthenticated temporary vIP. It does not make that row eligible for original-IP resolution.
- `publish_authenticated_vip(...)`: records an authenticated session's SourceToken/original-IP binding. State must be `ESTABLISHED` or `OVERLAP`.
- `resolve_original_ip(original_ip)`: returns only authenticated, unexpired `ESTABLISHED`/`OVERLAP` rows and prefers `ESTABLISHED` during rekey.
- `get_by_router_id(...)`, `get_by_source_token(...)`, and `get_by_original_ip(...)`: provide filtered table lookups. `get_by_original_ip()` excludes unauthenticated bootstrap rows by default.
- `remove(vip, session_id=...)`: removes an entry only if the current row belongs to that session ID.

The table's `originalIP` value follows the canonical IPv6 address from the Router Directory Record's `wan_endpoints[0]`, not the vIP or SourceToken. A table row is not an authorization by itself: the handshake runtime creates authenticated rows only after the full peer-trust and key-confirmation path succeeds.

## Routing boundary

NLS table updates do not automatically add or replace kernel routes. Routes remain operator-configured and are installed through the existing routing path. Router-CA records and pending vIP rows must never create routes on their own. `originalIP` is used to select and inspect a live authenticated NLS session; it is not proof that arbitrary traffic or prefixes are authorized.

## Specification conformance gap

The current `VIPManager` implementation still allocates a temporary random `/128` from its configured private IPv6 pool. The current `docs/nls/MASTER_SPEC.md` hybrid vIP amendment instead specifies a SHA-512-derived candidate using both routers' authoritative originalIP values, canonical certificate/public-key encodings, a fresh 32-byte nonce and a 30-second time bucket, with the pinned `2000::/3` policy. Those are not interchangeable algorithms. The implementation must not be described as fully conformant to that vIP-derivation amendment until the runtime carries and validates those fields and the two sides derive the same candidate in the real handshake lab. This table change addresses lifecycle/state visibility only; it does not silently rewrite the vIP derivation algorithm.

## Verification status

Unit tests cover pending-row retention, exclusion from authenticated lookup, collision rejection, originalIP publication, session-scoped deletion and selection of the new row during rekey overlap. The full gate remains conditional on CI and WAN-lab evidence: successful M1–M4 handshake, vIP retirement, traffic forwarding/return path and exact-head runs on Ubuntu 22.04 and 24.04.
