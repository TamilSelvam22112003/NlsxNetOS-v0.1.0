# NLS v1 handshake

**Status:** NLH2 M1–M4 and the NLE2 session-key data plane are implemented on `feat/nls-v1`. Prompt 1–3 gates are accepted. The Prompt 4 implementation/test head `efacc12f828c2a67cae781a56f98fd4486267dbf` passed Actions run [38892600029](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38892600029) (12/12 jobs), with ShellCheck and CodeQL also passing. This CI evidence does not replace independent security review. The daemon dispatches NLH2 only; legacy NLSH helpers remain for compatibility and are not dispatched. **legacy NLE1 removed; NLE2 is the only data path.** NAT traversal remains NOT VERIFIED.

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
The earlier `new_init`/`responder_key` JSON handshake used a self-asserted certificate dictionary and lacked live CA cross-checks; the earlier daemon also used identity-keyed blocking. These are historical findings for the superseded legacy path. The active daemon now dispatches NLH2 and performs signed-directory checks at S3/S4. The former NLE1 statements below are historical and do not describe the active data path.

## Prompt 3 implementation status

The active daemon dispatches NLH2 M1–M4 and uses verified Router-CA directory records for peer discovery. The Prompt 3 implementation gate passed on its recorded exact head; run 38874400473 is historical only and must not be used as evidence for current data-plane behavior. NAT traversal is not implemented or verified.

## NLE2 data plane (current)

After M4, peers use the derived directional session keys and IV prefixes for NLE2 packets. The NLE2 fixed 32-byte header is authenticated as AES-256-GCM AAD; the 64-bit sequence number is bound into the nonce as IV-prefix || sequence. The receiver checks session identity and direction, verifies AEAD before advancing the replay window, and rejects malformed, replayed, out-of-window, or unauthorized inner packets. No per-packet RSA wrap/unwrap is used in the data path; RSA remains only where the handshake envelope requires it.

The destination validates the inner source against the peer's verified RDR prefixes and the inner destination against explicit local/peer prefix policy before writing the inner packet to TUN. Session lifecycle includes make-before-break rekey, overlap expiry and best-effort mutable-buffer zeroization, plus teardown on revocation or loss of CA freshness. Python cannot guarantee erasure of immutable copies or native-library buffers.

Current implementation/test head `efacc12f828c2a67cae781a56f98fd4486267dbf` passed Actions run `38892600029`. Both strict-xfail commands reported 26 passed with no xfails; both six-node labs passed, including TCP/UDP, return path, route-table assertions, and WAN-node pcap confidentiality. The end-to-end 100 Mbit/s target is not met; see `Documentation/NLE2_PERFORMANCE.md`. Startup route testing allows only the kernel-generated `fe80::/64 dev nls0 proto kernel metric 256 pref medium` route; no other route-table change is permitted. NAT traversal remains **NOT VERIFIED**.
