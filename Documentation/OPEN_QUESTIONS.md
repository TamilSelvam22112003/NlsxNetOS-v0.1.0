# Open questions and safe interpretations

1. vIP layout: fd byte + 40 random bits + 16-bit subnet + random 64-bit IID. Safe default: vip.pool=fd00::/8, vip.layout=fd40-subnet16-iid64, operator-configured subnet, collision checks.
2. Internet vIP: select only inside the router's own operator-configured routable prefix; never invent public address space.
3. RDR signature: exact ASCII NLS-DIR-v1 + canonical CBOR of unsigned RDR. Signed lookup wrapper binds echoed nonce; freeze one schema and byte-test.
4. Transcript hashes: hash each canonical plaintext/authenticated envelope preceded by fixed-width network-order length, identically on both peers.
5. M1 padding: policy defines maximum M2 size; cap fields, pad M1 to maximum, reject oversized M2 before expensive crypto.
6. X.509 root and Ed25519 directory signer are separate out-of-band trust pins.
7. Offline mode: opt-in signed bundle, visibly degraded freshness, fail closed at expiry, stale-grace zero unless policy explicitly approved.
8. NAT/multihoming: current endpoint equality prevents NAT. Any relaxation must be explicit config policy and match CA-authorized endpoints.
9. WAN role: confirm exact config key; safe default fail closed unless selected WAN is enabled and eligible for vIP assignment.
10. CA data never creates routes; only operator route configuration reaches route installation.
11. Both control_protocol.py copies must parity-test constants, canonicalization, signature preimage, framing and errors.
12. Crash cleanup tracks only NLS-owned vIPs and never deletes operator-owned addresses.