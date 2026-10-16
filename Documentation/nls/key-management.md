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
**Current gap:** nls/handshake.py:derive_session uses a different salt/info; NLSDaemon stores send_key/recv_key but nls/encapsulation.py uses a new RSA-wrapped AES key per data packet. This is a sender-authentication flaw.