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
17. Performance record is in `Documentation/NLE2_PERFORMANCE.md`. Current exact-head Actions run 38892600029 measured in-process seal/open round trips of 278.18 Mbit/s on Ubuntu 22.04 and 376.11 Mbit/s on Ubuntu 24.04 for 1,280-byte packets over 20,000 iterations. End-to-end netns iperf3 offered 200 Mbit/s for 5 seconds; delivered 15.93 Mbit/s estimated on Ubuntu 22.04 (92.04% loss) and 2.67 Mbit/s receiver-measured on Ubuntu 24.04 (98.26% loss). The end-to-end target is NOT MET. The likely bottleneck is outside AEAD in the per-datagram TUN/socket/parser/event-loop path; no sampling profiler or per-stage CPU timing was collected, so attribution remains a hypothesis. A bounded TUN/UDP batching trial was reverted because it did not materially improve throughput.

## Prompt 4 lifecycle and time notes

18. Simultaneous rekey arbitration is deterministic: router IDs define the winner; the new session is installed before old sessions enter overlap, and old sessions are removed and their mutable key buffers overwritten after the configured overlap. The focused tests cover threshold triggers, simultaneous arbitration, queue handoff, and old-session zeroization. The high-rate iperf test uses the production packet limit so it measures forwarding rather than repeatedly forcing test-only rekeys.
19. Directory lookup freshness permits at most 30 seconds of age: 29 seconds old is accepted and 31 seconds old is rejected. `issued_at` has zero tolerated future skew; `valid_until` must be current and no more than 30 seconds ahead. Handshake message timestamps use a separate configurable skew (default 120 seconds), while the handshake state timeout is 5 seconds. The daemon checks trust on each Router-CA heartbeat; with stale-grace default 0, CA freshness loss fails closed and tears down sessions within one heartbeat interval plus the loop's 1-second bound.
20. Session traffic keys are held in mutable `bytearray` buffers and overwritten on session removal where possible. Python cannot guarantee secure erasure of immutable `bytes` copies, temporary objects, allocator remnants, or copies held inside cryptography/OpenSSL; garbage collection is not a zeroization guarantee. This is best-effort memory hygiene, not a proof of physical erasure.
21. The WAN-node pcap confidentiality test `test_pcap_contains_no_inner_packet_or_source_plaintext` passed in the current strict-xfail scaffold suite. Prompt 4 implementation/test head `efacc12f828c2a67cae781a56f98fd4486267dbf` passed all 12 jobs in Actions run 38892600029; see `Documentation/TRACEABILITY.md`. NAT traversal remains **NOT VERIFIED**. Independent security review remains outstanding.


## Prompt 5 carry-forward — provisioning and rollback

22. Pinned-key provisioning is only specified at the configuration-contract level: the X.509 root certificate and Ed25519 Router-CA directory-signing key are separate out-of-band trust pins; the latter is Base64-encoded raw 32-byte material at `router_ca.server_public_key` in `/etc/nlsxnetos/router-ca-client.yaml`. The repository does not yet provide a complete operator procedure for independently verifying the fingerprint, auditing installation, rotating/replacing the pin, or handling emergency rotation. Use `Documentation/PROMPT5_RUNBOOK.md` to close this gap; never use trust-on-first-use.
23. Directory rollback markers are currently file-backed in the signed cache `/var/lib/nlsxnetos/security/router-directory.json`: the signed bundle's `directory_seq` and per-router lookup `record_seq` values are compared against the previous cache during ordinary updates/import. Writes are atomic, but the monotonic mark is not independently protected. Restoring an older cache/snapshot can restore the older mark and defeat local rollback detection. Prompt 5 must choose and test rollback-resistant storage or explicitly constrain the threat model; no TPM-backed counter or external append-only marker is implemented.
24. Added Prompt 4 follow-up regressions: named default TUN MTU assertion; relay packet tamper/replay/forged-high-sequence test; five-repeat concurrent make-before-break packet-switch stress test; one-second-heartbeat revocation teardown bound; route-table snapshots around directory sync and signed bundle import. The full six-node integration test now explicitly names the large-payload MTU/fragmentation path. These additions require the new exact-head CI run; do not mark them passed until the run finishes.
25. Daemon profiling/low-rate validation is being added to the six-node workflow: cProfile profiles both daemon processes during an offered 2 Mbit/s UDP test on Ubuntu 22.04 and 24.04. The prior high-rate run was not lossless and no sampling profile existed; use the new exact-head artifacts to identify the measured bottleneck rather than relying on the previous hypothesis.
