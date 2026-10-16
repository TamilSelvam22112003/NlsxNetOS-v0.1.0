# NLS v1 protocol specification

**Status:** normative target, not a claim of current conformance. Current code uses NLSH/JSON and NLE1 per-packet RSA-wrapped AES keys; target is NLH2/NLE2 with signed CA directory records and session-derived directional keys.

## Roles and trust boundaries
Router S protects client-LAN packets; Router D authenticates S, decrypts, enforces S's inner-source prefixes, and forwards through kernel routing; Router-CA enrolls routers, issues certificates, maintains registry/revocation, signs Router Directory Records (RDRs), and distributes policy. Intermediate routers are ordinary IPv6 forwarders. The X.509 CA root and Ed25519 directory-signing key are distinct trust anchors pinned out of band.

## Suite and RDR
The only suite is X25519, HKDF-SHA256, AES-256-GCM, Ed25519 signatures, and RSA-OAEP-SHA256 with RSA-3072 for handshake key wrapping. Use cryptography primitives only; deterministic CBOR uses pinned cbor2 with canonical encoding. Reject all-zero X25519 secrets; use OS CSPRNG; never log keys, tokens, plaintext packets, or canaries.
RDR fields: router_id, ed25519_public_key, rsa_encryption_public_key, wan_endpoints, gateway_ips, prefixes, certificate_serial, status (ACTIVE/REVOKED/DISABLED/EXPIRED), record_seq, issued_at, valid_until. Signature preimage is exact ASCII NLS-DIR-v1 followed by canonical CBOR of unsigned record. Lookup(router_id, client_nonce) returns signed RDR plus same nonce, valid <=30 s. Signed bundles contain RDRs, revoked serials, policy, issued_at and valid_until; default lifetime 10 min. stale-grace defaults to zero; stale trust fails closed.

## Strict stages
S1: validate X.509 chain to pinned root, CN=router_id, matching CA-signed RDR, ACTIVE status, and validity.
S2: S allocates fresh random IPv6 /128 from vip.pool, assigns it to WAN using ip -6 addr add with nodad, TTL 10 s. M1/M2 use vIP. Pad M1 to at least maximum permitted M2 size.
S3: S live-looks-up D, compares every M2 field with RDR and policy, aborts on mismatch/downgrade, then sends M3.
S4: D live-looks-up S, compares M3 and M1 keys against authoritative RDR, aborts on mismatch, derives keys and sends M4.
S5: after S verifies M4, both sides bind to CA-validated real WAN endpoints; S removes vIP immediately. Later traffic from retired vIP drops with VIP_AFTER_SWITCH.
Failures drop silently on wire, tear down state, and emit stable local reason codes. Handshake timeout 5 s; minimal state until M3; cap pending handshakes; rate-limit by observed outer source, never claimed identity.

## State machines
S: IDLE -> AUTHENTICATE -> ASSIGN_VIP -> SEND_M1 -> WAIT_M2 -> LOOKUP_D -> CHECK_M2 -> SEND_M3 -> WAIT_M4 -> CHECK_M4 -> SWITCH -> ESTABLISHED. Failure/timeout cleans up vIP and ephemeral material.
D: LISTEN -> SCREEN_M1_WITH_CACHED_RDR -> SEND_M2 -> WAIT_M3 -> LOOKUP_S -> CHECK_M3_AND_M1 -> DERIVE_KEYS -> SEND_M4 -> BIND_REAL_ENDPOINT -> ESTABLISHED. Early screening does not replace S4.
CA: AUTHENTICATE_REQUEST -> CHECK_NONCE/ROUTER -> READ_REGISTRY/REVOCATION -> BUILD_RDR/BUNDLE -> SIGN_CANONICAL_CBOR_WITH_NLS-DIR-v1 -> RETURN. Unknown, stale, revoked, disabled, expired or nonce-mismatched requests fail closed. CA never sends session keys.

## Wire and data plane
Handshake envelope: NLH2 magic(4) | version=1(1) | type(1) | session_id(16) | envelope_length:u16be(2) | SEAL envelope; fixed prefix 24 bytes. Payload is deterministic CBOR. Reject unknown types/versions, oversized/inconsistent lengths and trailing bytes. SEAL generates random 32-byte AES key and 12-byte nonce, wraps key with RSA-OAEP-SHA256, encrypts with AES-256-GCM; AAD binds magic/version/type/session_id. Ed25519 signature is inside plaintext (sign-then-seal).
NLE2 data header: magic(4) | version=2(1) | flags=0(1) | reserved=0(2) | session_id(16) | seq(8), exactly 32 bytes and used as AAD. Nonce = directional 4-byte IV prefix || 64-bit sequence. c2s/s2c use separate keys; original IP packet including source/destination is encrypted; header has no inner addresses; no per-packet RSA. Authenticate before updating 128-packet replay window. D rejects inner sources outside S's RDR prefixes by default. Rekey make-before-break at 2^32 packets or one hour. IPv6+UDP+NLE2+tag overhead = 40+8+32+16 = 96 bytes; TUN MTU <= path MTU - 96.
Stable codes: NLS_AUTH_CERT_INVALID, NLS_AUTH_RDR_INVALID, NLS_CA_LOOKUP_STALE, NLS_CA_LOOKUP_MISMATCH, NLS_HS_FORMAT_INVALID, NLS_HS_SIGNATURE_INVALID, NLS_HS_TRANSCRIPT_MISMATCH, NLS_HS_TIMEOUT, NLS_HS_RATE_LIMITED, NLS_VIP_ASSIGN_FAILED, NLS_VIP_AFTER_SWITCH, NLS_AEAD_INVALID, NLS_REPLAY_DUPLICATE, NLS_REPLAY_OUT_OF_WINDOW, NLS_INNER_SOURCE_UNAUTHORIZED, NLS_SA_DOWNGRADE, NLS_CA_UNAVAILABLE, NLS_ROUTE_NOT_OPERATOR_CONFIGURED. Logs contain only reason codes and non-secret diagnostics.
**Current warning:** this is target contract. Runtime remains NLSH/JSON and NLE1/RSA-per-packet; see threat-model.md and TRACEABILITY.md.