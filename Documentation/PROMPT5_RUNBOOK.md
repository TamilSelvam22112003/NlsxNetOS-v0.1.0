# Prompt 5 operational runbook and carry-forward items

Status: engineering handoff only. NLS remains experimental; do not deploy to production or defence networks until Prompt 5 validation and independent security review are complete.

## Active protocol and operational assumptions

- The active data path is NLE2 only: fixed 32-byte authenticated header, directional AES-256-GCM session keys, and no per-packet RSA key wrapping. RSA is used only by the existing handshake envelope where specified.
- Router-CA lookups and signed directory bundles authorize peer identity and prefixes; they do not install Linux routes. Only explicit operator route configuration is allowed to change routes.
- Default stale-grace is zero. Loss of directory freshness or revocation tears down affected sessions; NAT traversal remains **NOT VERIFIED**.
- NLE2's configured default TUN MTU is 1400. The documented outer overhead budget is 96 bytes; for a 1500-byte WAN MTU, the theoretical safe inner MTU is 1404, so 1400 leaves a small margin. Confirm path MTU across every actual deployment path.

## Pinned-key provisioning — partially documented, operational procedure still required

The repository documents that two independent trust anchors are required:

1. The X.509 root CA certificate, configured as the certificate trust anchor for router certificates.
2. The Router-CA directory-signing Ed25519 public key, configured in `/etc/nlsxnetos/router-ca-client.yaml` under `router_ca.server_public_key` as Base64-encoded raw 32-byte key material.

The directory verifier rejects a bundle signer that does not exactly match the configured pin. The README and handshake documentation state that the directory signer and X.509 root are provisioned out-of-band; signed bundles do not establish or replace the pin.

**Still required for Prompt 5:** a step-by-step, operator-verifiable provisioning procedure that obtains the key fingerprint through an independently authenticated channel, records who verified it and when, sets file ownership/permissions, validates the installed pin, and defines approved key rotation/replacement and emergency rollback. Do not use trust-on-first-use or copy the key only from the same bundle whose signature it is meant to verify. The repository does not currently define a tested dual-pin rotation protocol.

## Directory rollback-mark storage — file-backed, not rollback-resistant

The current implementation stores the signed directory bundle and its `directory_seq` in the verified directory cache (normally `/var/lib/nlsxnetos/security/router-directory.json`). Per-router lookup envelopes and their `record_seq` values are also retained in that cache. Writes are atomic and incoming directory/record sequences are compared against the values already on disk. Offline bundle import similarly compares the new sequence with the previously loaded bundle.

This protects against ordinary stale or lower-sequence updates while the current cache remains intact. **It is not a protected monotonic counter:** restoring an older backup or snapshot of the whole cache can restore the older rollback mark too. No TPM-backed counter, append-only external ledger, or independently protected sequence database is established by the current implementation.

**Prompt 5 decision required:** choose and document a rollback-resistant persistence mechanism appropriate to the deployment threat model. Until then, explicitly state that a privileged attacker or disk/snapshot rollback can defeat local sequence-memory guarantees. Add tests for process restart, cache restore, stale bundle import, record-sequence rollback, and recovery from interrupted atomic writes.

## Prompt 4 validation inventory and remaining depth

- MTU/fragmentation: the six-node lab exercises inner payload sizes 1200, 1280, 1350 and a large 1380-byte ping payload with the lab TUN MTU set to 1280. The default-MTU unit test asserts 1400. Keep these as separate named regressions; confirm whether fragmentation is expected inside the tunnel or whether the deployment must reject/avoid it.
- Relay abuse: `test_relay_abuse_tampered_and_replayed_datagrams_rejected` covers packet tampering, replay, and forged high-sequence poisoning at the NLE2 packet boundary. Prompt 5 should add a full WAN-relay integration scenario that attempts drop, replay, reorder, and packet modification while measuring receiver delivery; the current test is not a full active relay process.
- Route isolation: the six-node lab snapshots the actual IPv6 route table across daemon startup, CA lookup/handshake and has an operator-route positive control. Security tests now snapshot the host IPv6 route table around directory synchronization and signed bundle import. Prompt 5 should retain route snapshots on the actual isolated router namespaces for both operations, not only the test host.
- Rekey under traffic: the spec now runs five repeated concurrent make-before-break traffic transitions and checks every captured packet decrypts under its session key with no sequence gaps. This is a deterministic in-process stress test, not yet a simultaneous two-router rekey over the full netns/TUN/UDP path. Add that full integration test and assert zero loss across repeated runs before treating the concurrency requirement as complete.
- Revocation timing: the focused regression models a one-second trust heartbeat, applies revocation at the next tick, and checks teardown within heartbeat + 1 second plus key-buffer zeroization. Add an end-to-end daemon-loop test that revokes a peer through the signed directory and measures wall-clock teardown without manually calling the trust-refresh method.
- Performance: Actions run [38894080929](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38894080929) profiled both daemons with Python `cProfile` on Ubuntu 22.04 and 24.04 during a 2 Mbit/s, 5-second UDP test with 1,280-byte inner packets. Ubuntu 22.04 delivered 1.995 Mbit/s at 0% reported loss; Ubuntu 24.04 delivered 2.001 Mbit/s at 0% reported loss. Profiles show repeated per-packet route config/YAML parsing on send and repeated signed directory/RDR verification and RSA public-key parsing on receive. The cheap sender-side route cache fix is now in `nls/routing.py`, with config-change invalidation coverage. The exact-head rerun after this fix is queued; do not claim post-fix improvement until it finishes. The previous 200 Mbit/s benchmark had severe packet loss and did not meet the 100 Mbit/s target; do not claim the target is met from the in-process AEAD benchmark.
- Confidentiality: retain `test_pcap_contains_no_inner_packet_or_source_plaintext` as a strict pass, not an xfail.
- External validation: NAT traversal is **NOT VERIFIED** and independent security review is outstanding.

## Prompt 5 exit criteria

1. Approve and document out-of-band pinned-key provisioning, pin rotation, and rollback/recovery.
2. Decide how rollback marks survive privileged cache restore and prove the selected design with restart/restore tests.
3. Pass the full netns concurrent-rekey and live-revocation timing tests, in addition to unit stress tests.
4. Review both OS profiling artifacts and the 2 Mbit/s receiver loss results; document the measured bottleneck and any optimization evidence.
5. Re-run the full exact-head CI gate after all code and documentation changes.
6. Record unresolved items explicitly; passing CI is not an independent security certification.
