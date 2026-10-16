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

## Prompt 4 carry-forward constraints

13. Inner destination authorization uses explicit verified RDR prefix policy; do not delegate it to kernel routing without a lab firewall-drop test.
14. Signed lookup freshness: maximum age 30 seconds (29 seconds accepted, 31 rejected), zero tolerated future skew for issued_at, valid_until no more than 30 seconds ahead. Handshake timestamp skew is separately configured (default 120 seconds); handshake timeout is 5 seconds.
15. CA-driven lookup, directory sync, bundle import, and handshake completion must leave the actual IPv6 route table unchanged. The explicit operator route is the positive control and should be the only supported route mutation path.
16. The pcap confidentiality test remains deferred only if a WAN-node capture cannot be run in the lab; document that limitation and complete it in Prompt 5. NAT traversal remains NOT VERIFIED.
17. Prompt 4b must document simultaneous-rekey arbitration, key lifetime/zeroization limitations, CA freshness teardown, and benchmark method/results. If the Ubuntu 24.04 runner misses 100 Mbit/s with 1,280-byte packets, record the measured result and bottleneck rather than hiding it.
