# NLS v1 handshake

**Status:** target specification; current code does not implement this flow. Current nls/handshake.py exposes NLSH, INIT/RESPONSE and JSON canonicalization.

## Encoding
Use deterministic CBOR (cbor2 canonical=True). Datagram: NLH2 | version:u8=1 | type:u8 | session_id:16 | envelope_length:u16be | SEAL; fixed prefix 24 bytes. SEAL uses fresh 32-byte AES key, RSA-OAEP-SHA256 wrapping, random 12-byte nonce, AES-256-GCM and AAD=magic||version||type||session_id. Ed25519 signature is inside plaintext. Reject bad lengths, unknown type/version, malformed schema and trailing bytes.

## M1 — S to D
S validates its X.509 chain and RDR against pinned trust anchors; status must be ACTIVE, certificate/record unexpired and serial unrevoked. S allocates and assigns fresh /128 vIP with nodad, TTL 10 s. M1 plaintext: session_id, S.router_id, S.ed25519_public_key, S.rsa_encryption_public_key, nonce_s, timestamp, vip, sig_S. Seal to D's RSA key from verified CA directory. Outer source=vIP, destination=D's RDR WAN endpoint. Pad M1 to at least maximum permitted M2 size. D screens claimed keys/status against cached signed RDR before expensive state allocation; this does not replace S4.
## M2 — D to vIP
M2 plaintext: session_id, D.router_id, D.certificate, D.RDR, gateway_ips, sa_proposals, dh_pub_D, nonce_d, ike_meta, H1=hash(M1 plaintext), sig_D. Seal to S's RSA key from authoritative cached directory, never an untrusted M1 claim.
## S3 and M3
S calls Lookup(D, client_nonce), verifies pinned directory signature with NLS-DIR-v1, nonce echo, <=30 s freshness, ACTIVE status and certificate validity. Compare every M2 field: serial, Ed25519/RSA keys, WAN endpoint, gateway IPs, suite proposals and minimum version. Any mismatch/revocation/staleness/downgrade aborts. M3 plaintext: session_id, S.certificate, S.RDR, dh_pub_S, chosen_sa, S.wan_endpoint, H2=hash(M1..M2), sig_S. Seal to D's RSA key from S's verified CA record.
## S4 and M4
D fresh-looks-up S and compares M3 and M1 keys to authoritative RDR. On mismatch aborts. On match derives keys and sends M4 sealed to S's RDR RSA key. M4 plaintext: session_id, trust=true, H3=hash(M1..M3), confirm=HMAC-SHA256(k_confirm,H3), sig_D. S verifies identity/signature/session/transcript and constant-time compares confirm before endpoint switch.
## State and cleanup
Hash transcript elements with fixed-width length prefixes to avoid ambiguous concatenation; exact choice is in OPEN_QUESTIONS.md. Timeout 5 s; cap pending handshakes; rate-limit by observed source, never claimed identity. Malformed M1 must not block a legitimate router. Abort/timeout removes vIP and discards ephemeral state.
## Source findings
new_init builds self-asserted certificate dict and signs JSON; no live CA lookup. responder_key checks local values but no X.509 chain or S3. NLSDaemon._send_init requires CA endpoint equal local source/listen endpoint. NLSDaemon._handle_init blocks mapped peers on failure. M1–M4 is not implemented.