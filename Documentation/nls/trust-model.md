# NLS v1 trust model

X.509 CA root validates router certificate chains. The Router-CA control identity Ed25519 key is pinned out of band and verifies RDR/bundle signatures using NLS-DIR-v1 plus canonical CBOR of unsigned object. Router identity key is in certificate/RDR with CN=router_id; RSA-3072 encryption key is bound by RDR. Never trust a router-supplied certificate dictionary or unsigned YAML as authority.

RDR contains router_id, Ed25519 key, RSA key, WAN endpoints, gateway IPs, prefixes, serial, status, record_seq, issued_at, valid_until. Require ACTIVE and matching keys/endpoints/serial plus valid certificate and record. Lookup echoes fresh client_nonce; response valid <=30 s. Bundles expire after 10 min; stale-grace=0. Offline mode is opt-in, verifies signed bundle, marks degraded freshness, and fails closed at expiry.

Enforce revocation during handshake and session refresh. Policy fixes allowed suites, minimum versions, replay window and timeouts. CA failure/stale lookup/downgrade fails closed in ca mode. CA data may authorize a peer/prefix but never create a route; only operator-configured nls route PREFIX via ROUTER-ID creates TUN routes. D validates decrypted inner source against S's RDR prefixes by default.
Prompt 5a implementation status: the NLS v1 handshake path uses signed, nonce-bound Router-CA lookups and directory records; the daemon accepts only operator-configured routes, and the Router-CA client agent refreshes the signed directory/revocation cache. The receive-path cache now checks the cache content hash against a separate mode-0600 rollback mark, retains record/directory sequence high-water marks, and rejects stale bundles or revoked records. The daemon polls the verified cache once per second so revocation teardown can add at most one second after the CA agent's heartbeat interval.

**Acceptance status: NOT VERIFIED until the current head has green Actions evidence.** The real two-router lab now exercises a live Router-CA, WAN pcap confidentiality, unauthorized inner-source relay abuse, ten simultaneous-rekey traffic cycles, and CA revocation timing. Throughput matrix, fresh cProfile outputs, rollback-cache tests, packaging/install tests, and Ubuntu 22.04/24.04 results must be reviewed from the exact run/head before this status can be upgraded. Keep the product labeled **experimental, not independently reviewed**.

**Carry to Prompt 5b — NOT VERIFIED:** authenticated control-identity rotation and cross-version clock-skew boundary tests (lookup validity, certificate validity edges, and time-based rekey). Full-disk snapshot restoration or root access can restore both the directory cache and its separate rollback mark; the mark is not a hardware-backed monotonic counter.

## Verified directory receive cache and rollback mark

The receive path caches verified Router Directory Records for at most `min(heartbeat_seconds, 5 seconds)`. It invalidates/reverifies when the cache content hash, signed `directory_seq`, a record's `record_seq`, the policy file, the revocation file, bundle `expires_at`, record `valid_until`, or trust freshness changes. Revoked or non-ACTIVE records are never returned as trusted peers. Parsed Ed25519 and RSA public keys are cached by their exact encoded key material; a changed key string creates a distinct parsed-key cache entry.

The local rollback mark is `/var/lib/nlsxnetos/rollback/directory-rollback-mark.json`, outside the directory cache at `/var/lib/nlsxnetos/security/router-directory.json`. It is written atomically, file and parent directory are fsynced, and the mark is mode `0600`, owned by `nlsxnetos:nlsxnetos`. Directory and record sequence high-water marks move forward only. Missing/corrupt marks, cache-hash mismatch, or sequence mismatch fail closed until a fresh signed live sync. In offline mode, re-import requires the explicit `import-bundle --confirm-rollback-reset` operator flag.

This is a software rollback mark, not a hardware monotonic counter. Full-disk snapshot restoration or root access can restore both the cache and its mark and defeat this protection. Those limitations remain explicit; the product is **experimental, not independently reviewed**.


## Verified receive-cache refresh and freshness trade-off

NLS keeps Router-CA-verified directory records in process memory so packet processing does not stat, open, hash, or parse the directory cache for each packet. The hot path performs an in-memory router-id lookup and scalar checks for directory-bundle expiry, record `valid_until`, ACTIVE status, and the already-verified revocation set.

The cache refresh deadline is `min(heartbeat_seconds, 5 seconds)`. At refresh, NlsxNetOS checks file signatures, reads the cache/rollback mark/revocation/policy state, verifies signatures and rollback invariants, and rebuilds the in-memory records. The daemon's trust monitor polls at one-second intervals and removes sessions when verified freshness is lost, a peer is revoked/disabled/expired, or a record changes incompatibly.

**Security trade-off:** a local tamper or replacement of cache files may go unnoticed until the next refresh, bounded by the configured heartbeat (and capped at five seconds by this implementation). The daemon must still tear down revoked sessions within heartbeat plus one second; the live six-node revocation test checks this with established, warmed sessions. Signed bundle expiry and per-record `valid_until` are checked on every access and must stop traffic even while the cache entry is warm. Missing or invalid cache/rollback state fails closed when refresh occurs.
