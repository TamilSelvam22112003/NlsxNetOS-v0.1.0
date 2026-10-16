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
16. The WAN-node pcap confidentiality test is now active and passed in scaffold CI; retain the pcap test in the final exact-head gate. NAT traversal remains NOT VERIFIED.
17. Performance record is in `Documentation/NLE2_PERFORMANCE.md`. Exact-head run 38890480995 (implementation SHA `a779ed904ebc13b0f86321999945af30a9abdc15`) measured in-process seal/open round trips of 282.41 Mbit/s on Ubuntu 22.04 and 365.89 Mbit/s on Ubuntu 24.04. End-to-end netns iperf3 delivered 6.46 Mbit/s estimated on Ubuntu 22.04 and 3.22 Mbit/s receiver-measured on Ubuntu 24.04, with 96.77% and 97.48% loss respectively at 200 Mbit/s offered rate. The end-to-end target is NOT met. Bounded TUN/UDP batching was trialed but reverted because it did not materially improve throughput. The likely bottleneck is outside AEAD in the single-threaded per-datagram TUN/socket/event-loop path; exact stage-level profiling is still open. Do not claim the in-process result as end-to-end throughput.

## Prompt 4 lifecycle and time notes

18. Simultaneous rekey arbitration is deterministic: router IDs define the winner; the new session is installed before old sessions enter overlap, and old sessions are removed and their mutable key buffers overwritten after the configured overlap. The focused tests cover threshold triggers, simultaneous arbitration, queue handoff, and old-session zeroization. The high-rate iperf test uses the production packet limit so it measures forwarding rather than repeatedly forcing test-only rekeys.
19. Directory lookup freshness permits at most 30 seconds of age: 29 seconds old is accepted and 31 seconds old is rejected. `issued_at` has zero tolerated future skew; `valid_until` must be current and no more than 30 seconds ahead. Handshake message timestamps use a separate configurable skew (default 120 seconds), while the handshake state timeout is 5 seconds. The daemon checks trust on each Router-CA heartbeat; with stale-grace default 0, CA freshness loss fails closed and tears down sessions within one heartbeat interval plus the loop's 1-second bound.
20. Session traffic keys are held in mutable `bytearray` buffers and overwritten on session removal where possible. Python cannot guarantee secure erasure of immutable `bytes` copies, temporary objects, allocator remnants, or copies held inside cryptography/OpenSSL; garbage collection is not a zeroization guarantee. This is best-effort memory hygiene, not a proof of physical erasure.
21. The WAN-node pcap confidentiality test is active. NAT traversal remains **NOT VERIFIED**. The Prompt 4 gate remains pending until all jobs pass on the same final head and the updated benchmark/lab output is recorded.
