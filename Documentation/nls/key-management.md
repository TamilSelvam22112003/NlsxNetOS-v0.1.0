# NLS v1 key management

## Keys
Router identity is Ed25519 in an X.509 certificate with CN=router_id. Router encryption is RSA-3072 bound to identity by signed RDR. Router-CA directory signing is Ed25519 pinned out of band, domain-separated with NLS-DIR-v1. X.509 CA root and directory signer are distinct trust roles. Session keys are local X25519/HKDF outputs; CA never transports symmetric keys.

## Enrollment and handshake
Router generates keys locally. Enrollment includes RSA public key plus proof of possession; private key never leaves router. CA binds certificate serial, identity/encryption keys, WAN endpoints, gateway IPs, prefixes, status and record_seq. RSA-OAEP-SHA256/RSA-3072 wraps fresh AES keys for handshake envelopes M1–M4 only. Each envelope uses fresh 32-byte AES key and 96-bit nonce, AAD binds NLH2 header/session_id, signature is inside plaintext. No per-packet RSA.

## Session key schedule
1. shared=X25519(dh_S,dh_D); reject all-zero secret.
2. salt=SHA256(H3||nonce_s||nonce_d).
3. HKDF-SHA256 derives c2s AES key (32 B), s2c AES key (32 B), c2s IV prefix (4 B), s2c IV prefix (4 B), k_confirm (32 B).
4. Unique versioned direction-specific HKDF info labels bind both router IDs.
5. M4 confirm=HMAC-SHA256(k_confirm,H3); compare in constant time.

Rekey make-before-break at 2^32 packets or one hour. Never reuse nonce with same key. On teardown remove session references, discard ephemeral keys, release vIP on every exit, reject old session IDs, and enforce certificate expiry/revocation on admission and refresh.
**Current implementation status:** the NLS v1 data path derives direction-specific AES-256-GCM keys from X25519/HKDF and uses NLE2 session keys for data packets; RSA-OAEP is confined to handshake envelopes. The implementation remains **experimental, not independently reviewed** until the Prompt 5a acceptance gate and subsequent review pass.

## Router-CA control identity provisioning

The Router-CA control identity is a separate Ed25519 key from the X.509 certificate-signing key. Provision the control identity private key only on the CA host, with owner `nls-router-ca` (or the configured service account) and mode `0600`. Routers must receive the raw Ed25519 public key (base64-encoded in `router_ca.server_public_key`) through an authenticated out-of-band channel. Compare its SHA-256 fingerprint through a second channel before enabling `trust_mode: ca`. Do not bootstrap trust from an unsigned Router-CA YAML file or from a key learned during the first connection.

## Authenticated control-key rotation

The intended rotation procedure is staged: the currently pinned control key authenticates a transition statement containing the new public key, key identifier, activation time, expiry, and monotonic key epoch; the router verifies that statement under the old key, persists the epoch outside the directory cache, and accepts the new key only after the configured activation point. No silent fallback to an unpinned key is permitted.

**Status: NOT VERIFIED.** An end-to-end authenticated control-identity rotation protocol, durable key epoch, rollback handling during rotation, and cross-version rotation tests have not passed the Prompt 5a gate. Carry this item into Prompt 5b; do not treat manual key-file replacement as authenticated rotation.

## Clock skew and time validity

- Signed lookup responses are bound to the request nonce and have a maximum 30-second validity.
- Signed directory bundles expire after 10 minutes by default; stale grace defaults to zero.
- X.509 `notBefore`/`notAfter`, RDR `issued_at`/`valid_until`, and bundle expiry must all be checked before trust is granted.
- The CA control protocol's configured timestamp-skew allowance defaults to 120 seconds. Rekey scheduling uses a monotonic clock for the one-hour lifetime threshold; packet-count rekey is independent of wall-clock changes.
- Operators must keep router and CA clocks synchronized and investigate NTP steps or skew errors rather than increasing stale grace.

**Status: NOT VERIFIED.** Boundary tests for positive/negative clock skew, certificate validity edges, lookup expiry, bundle freshness loss, and time-based rekey on Ubuntu 22.04 and 24.04 remain outstanding for Prompt 5b.