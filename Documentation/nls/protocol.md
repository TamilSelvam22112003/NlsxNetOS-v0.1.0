# NLS v1 protocol specification

**Status:** Prompt 3's NLH2 M1–M4 handshake and signed Router-CA lookup gate passed on `feat/nls-v1` (GitHub Actions run [38874400473](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38874400473)). The active daemon dispatches NLH2 for handshakes. The NLE1 data plane still uses per-packet RSA-wrapped AES keys and retains known V3/V8 weaknesses; NLE2/session-key data protection is Prompt 4 work. This branch remains experimental, not independently audited, and not production-ready.

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
## Stable local error-code table

| Code | Meaning |
|---|---|
| NLS_AUTH_CERT_INVALID | Certificate chain, subject, validity or key binding failed |
| NLS_AUTH_RDR_INVALID | RDR signature, status, validity or key mismatch |
| NLS_CA_LOOKUP_STALE | Lookup/bundle freshness or nonce check failed |
| NLS_CA_LOOKUP_MISMATCH | CA record differs from peer message |
| NLS_HS_FORMAT_INVALID | Handshake envelope or CBOR schema invalid |
| NLS_HS_SIGNATURE_INVALID | Message signature invalid |
| NLS_HS_TRANSCRIPT_MISMATCH | Transcript/session/nonce binding failed |
| NLS_HS_TIMEOUT | Handshake exceeded 5 seconds |
| NLS_HS_RATE_LIMITED | Source-address rate limit reached |
| NLS_VIP_ASSIGN_FAILED | Temporary address could not be assigned |
| NLS_VIP_AFTER_SWITCH | Packet arrived from retired vIP |
| NLS_AEAD_INVALID | Data AEAD authentication failed |
| NLS_REPLAY_DUPLICATE | Sequence already accepted |
| NLS_REPLAY_OUT_OF_WINDOW | Sequence outside receive window |
| NLS_INNER_SOURCE_UNAUTHORIZED | Inner source not in source RDR prefixes |
| NLS_SA_DOWNGRADE | Suite/version violates CA policy |
| NLS_CA_UNAVAILABLE | Required live lookup failed and offline mode is not authorized |
| NLS_ROUTE_NOT_OPERATOR_CONFIGURED | Route request has no operator configuration |
| NLS_HS_MALFORMED | Invalid NLH2 framing, sealed payload, or CBOR schema |
| NLS_HS_M1_REJECTED | M1 failed local identity, signature, timestamp, vIP, or trust screening |
| NLS_HS_OUT_OF_ORDER | Message is not valid for the current session state |
| NLS_HS_REPLAY | Reused session ID or replayed handshake |
| NLS_HS_PENDING_LIMIT | Pending-handshake cap reached |
| NLS_HS_START_FAILED | Initiator could not begin a handshake |
| NLS_HS_VIP_INTERFACE_REQUIRED | Could not determine the WAN interface for vIP assignment |
| NLS_HS_S3_REJECTED | Initiator rejected M2 or S3 Router-CA cross-check |
| NLS_HS_S4_REJECTED | Responder rejected M3 or S4 Router-CA cross-check |
| NLS_HS_M4_REJECTED | Initiator rejected M4 or key confirmation |
| NLS_HS_SHUTDOWN | Pending handshake aborted during shutdown |
| NLS_HS_VIP_TTL_EXPIRED | Bootstrap vIP expired before handshake completion |
| NLS_VIP_CLEANUP_FAILED | Kernel vIP cleanup failed; recovery state is retained |
| NLS_HS_UNKNOWN_DATAGRAM | Datagram is not an accepted handshake or data packet |
| VIP_AFTER_SWITCH | Packet arrived from a bootstrap vIP after endpoint switch |

| NLS_DATA_PEER_KEY_MISSING | Destination router has no usable encryption key |
| NLS_DATA_MULTICAST_NOT_TUNNELED | Link-scoped multicast is not routed through NLS |
| NLS_DATA_SEND_FAILED | Queued NLS packet could not be sent |

Logs contain only reason codes and non-secret diagnostics.
**Current warning:** the active handshake runtime is NLH2/CBOR; the data plane remains NLE1/RSA-per-packet until Prompt 4. See threat-model.md and TRACEABILITY.md.

## Implementation status note (2026-10-16)

- Prompt 3 handshake, vIP lifecycle, signed RDR checks, endpoint switch, source-based rate limiting, structured drop reasons, and operator-only NLS route configuration are implemented on `feat/nls-v1`; the Ubuntu 22.04/24.04 and namespace-lab acceptance jobs passed in run 38874400473.
- Prompt 3's acceptance gate passed on implementation commit `471694a7946fa6c7ed98fa9f90aead09c9b43e98`; real Ubuntu 22.04/24.04 and namespace-lab evidence is recorded in TRACEABILITY.md and GitHub Actions run 38874400473.
- Temporary vIPs require a valid return route to the originating router during bootstrap. The lab configures static IPv6 routes for both endpoint pools. NAT traversal is not implemented or verified.
- Historical findings V1–V11 remain the baseline record; Prompt 3 addresses the handshake, vIP and route-installation findings, while the data-plane forgery findings remain open until Prompt 4.
