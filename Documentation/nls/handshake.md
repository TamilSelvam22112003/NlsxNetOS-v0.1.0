# NLS v1 handshake

**Status:** Prompt 3 NLH2 M1–M4 implementation and acceptance gate passed on `feat/nls-v1` (GitHub Actions run [38874400473](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38874400473)). The daemon dispatches NLH2 only; legacy NLSH helpers remain for compatibility and are not dispatched. The NLE1 data plane remains legacy until Prompt 4, so the branch is experimental and not production-ready.

## Encoding
Use deterministic CBOR (cbor2 canonical=True). Datagram: NLH2 | version:u8=1 | type:u8 | session_id:16 | envelope_length:u16be | SEAL; fixed prefix 24 bytes. SEAL uses fresh 32-byte AES key, RSA-OAEP-SHA256 wrapping, random 12-byte nonce, AES-256-GCM and AAD=magic||version||type||session_id. Ed25519 signature is inside plaintext. Reject bad lengths, unknown type/version, malformed schema and trailing bytes.

## M1 — S to D
S validates its X.509 chain and RDR against pinned trust anchors; status must be ACTIVE, certificate/record unexpired and serial unrevoked. S allocates and assigns a fresh random /128 from the configured private IPv6 pool with nodad, TTL at most 10 s. M1 plaintext: session_id, S.router_id, S.ed25519_public_key, S.rsa_encryption_public_key, nonce_s, timestamp, vip, padding, sig_S. Seal to D's RSA key from verified CA directory. Outer source=vIP, destination=D's RDR WAN endpoint. The current runtime uses a bounded 7,600-byte padding field to satisfy the configured M2 amplification budget. Pad M1 to at least maximum permitted M2 size. D screens claimed keys/status against cached signed RDR before expensive state allocation; this does not replace S4.
## M2 — D to vIP
M2 plaintext: session_id, D.router_id, D.certificate, D.RDR, gateway_ips, sa_proposals, dh_pub_D, nonce_d, ike_meta, H1=hash(M1 plaintext), sig_D. Seal to S's RSA key from authoritative cached directory, never an untrusted M1 claim.
## S3 and M3
S calls Lookup(D, client_nonce), verifies pinned directory signature with NLS-DIR-v1, nonce echo, <=30 s freshness, ACTIVE status and certificate validity. Compare every M2 field: serial, Ed25519/RSA keys, WAN endpoint, gateway IPs, suite proposals and minimum version. Any mismatch/revocation/staleness/downgrade aborts. M3 plaintext: session_id, S.certificate, S.RDR, dh_pub_S, chosen_sa, S.wan_endpoint, H2=hash(M1..M2), sig_S. Seal to D's RSA key from S's verified CA record.
## S4 and M4
D fresh-looks-up S and compares M3 and M1 keys to authoritative RDR. On mismatch aborts. On match derives keys and sends M4 sealed to S's RDR RSA key. M4 plaintext: session_id, trust=true, H3=hash(M1..M3), confirm=HMAC-SHA256(k_confirm,H3), sig_D. S verifies identity/signature/session/transcript and constant-time compares confirm before endpoint switch.
## State and cleanup
Transcript hashing uses length-prefixed M1/M2/M3 plaintexts via `transcript_h1`, `transcript_h2`, and `transcript_h3`; the HKDF schedule and confirmation MAC are implemented in `nls/key_schedule.py`. Timeout is 5 s; pending handshakes are capped; rate limiting is by observed source, never claimed identity. Malformed M1 does not create identity-keyed blocks. Abort/timeout removes the vIP and discards ephemeral state.
## Historical source findings (Prompt 1 baseline)
The earlier `new_init`/`responder_key` JSON handshake used a self-asserted certificate dictionary and lacked live CA cross-checks; the earlier daemon also used identity-keyed blocking. These are historical findings for the superseded legacy path. The active daemon now dispatches NLH2 and performs signed-directory checks at S3/S4.

## Prompt 3 implementation status

The active daemon dispatches NLH2 M1–M4 only and uses verified Router-CA directory records for peer discovery. GitHub Actions run 38874400473 passed the Ubuntu 22.04/24.04 package/unit/security suites, four-node namespace lab, ten-router IPv6 lab, fresh-install checks, dependency audit, and source-integrity check. NAT traversal is not implemented or verified. The legacy NLE1 data plane remains in place for Prompt 3 and retains the known V3/V8 limitations.
