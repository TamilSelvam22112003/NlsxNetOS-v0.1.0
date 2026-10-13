# NLS Bootstrap Privacy Envelope v1 (experimental)

The router boots with the Router-CA endpoint and CA RSA public key provisioned
out-of-band, checks IPv6 reachability, then sends its registration with source
IP/router identity/CSR/enrollment metadata inside an encrypted payload to the
CA public key. The CA decrypts and authorizes it, then encrypts its acknowledgement
to the enrolling router's registered RSA public key.

The helper uses a fresh AES-256 key and nonce per envelope, AES-256-GCM for
payload encryption, and RSA-OAEP-SHA-256 to wrap only the AES key. Version,
message type and visible destination are authenticated as AAD. RSA must not
encrypt the entire payload directly because RSA-OAEP has a strict plaintext
limit. Never trust a router key merely because it appears in an unauthenticated
request.

For router-to-router data packets, the inner packet must be encrypted to the
destination router/session key, not the Router-CA key. The CA is not the
data-plane recipient. The visible outer destination remains routable.

**Integration status:** `nls/bootstrap_envelope.py` and its unit tests provide
the experimental envelope primitive only. The Router-CA client, Core listener,
acknowledgement path, NLS packet dispatcher and TUN data plane still need to be
wired to this format and tested together. This is not yet a completed end-to-end
migration. Independent cryptographic review is required before production.
