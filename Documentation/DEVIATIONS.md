# Deviations and historical implementation notes — Prompt 2 through Prompt 4

- The verified directory cache is JSON-serialized for atomic persistence, but every trust-bearing envelope is re-verified over canonical CBOR with the out-of-band pinned Ed25519 control identity before use. The cache itself is not a trust anchor.
- Offline import rejects expired bundles and directory-sequence rollback. Offline mode is explicitly degraded because it cannot learn a new revocation until an operator imports a newer bundle.
- The directory-sync implementation consumes a full signed snapshot rather than incremental deltas.
- Historical Prompt 2 note: daemon revocation teardown was not yet wired at that gate. Prompt 4 adds active-session revocation and CA-freshness teardown; see the current lifecycle tests and traceability table.
- The previous unsigned YAML trust store is read-only/ignored as a trust source. Existing add/remove entry commands now fail closed and direct administrators to Router-CA registration/revocation and signed bundle import.
- Prompt 1 integration fixtures that formerly seeded unsigned YAML were migrated to generated, pinned-key signed directory bundles. This test change is intentional because accepting the old fixture format would violate the signed-directory requirement.


## Historical Prompt 3 implementation notes — superseded by Prompt 3 follow-up and Prompt 4

- The active handshake dispatch accepts NLH2 messages only. The legacy NLSH/JSON helper functions remain in `nls/handshake.py` for compatibility with old unit consumers, but the daemon's UDP receive loop does not dispatch legacy INIT/RESPONSE messages. The legacy NLE1 data path described in this historical section has since been removed.
- Existing `tests/unit/test_nls_handshake.py` was replaced with NLH2 tests for sealed message round-trip, recipient-key rejection, signature/transcript tampering, and strict unknown/missing-field rejection. Additional handshake acceptance coverage lives in `tests/security/test_nlh2_acceptance.py`.
- The vIP state file now retains `last_assigned` and `last_released` audit markers to make short-lived bootstrap addresses verifiable in namespace tests even when the M1–M4 exchange completes faster than an observer polling interval. These markers contain addresses only, not keys, tokens, or packet plaintext.
- The 10-router lab requires explicit return routes for both endpoint vIP pools. NAT traversal is not implemented or verified; deployments behind NAT remain unsupported/untested.
- At the Prompt 3 checkpoint, the data plane still used legacy NLE1 per-packet RSA wrapping. This is historical only; the current active data path is NLE2 with directional AES-256-GCM keys. Independent security review remains outstanding.
- Historical run 38874400473 passed on implementation commit 471694a7946fa6c7ed98fa9f90aead09c9b43e98, but it predates current branch-head edits and is not evidence for the current branch head.


## Prompt 3 follow-up — gate accepted on its recorded exact head

- The signed RDR comparison contract is explicitly defined by `RDR_S3_S4_COMPARE_FIELDS` in `nls/v2_runtime.py`: `router_id`, `ed25519_public_key`, `rsa_encryption_public_key`, `wan_endpoints`, `gateway_ips`, `prefixes`, `certificate_serial`, `status`, and `record_seq`. `issued_at`/`valid_until` are validated as per-lookup freshness metadata (not equality fields); policy fields are separately checked from the signed policy bundle.
- New tests exercise each of the nine RDR field mismatches at both S3 and S4, timestamp bounds, legacy NLSH INIT/RESPONSE rejection, operator route CLI validation, signed bundle import route non-mutation, and directory-sync route non-mutation. These tests passed on the recorded Prompt 3 exact-head CI run documented in `Documentation/TRACEABILITY.md`.
- The integration topology is now six namespaces: client, Router A, intermediate IPv6 WAN, Router B, server, and Router-CA namespace. It emits `NLS_VIP_BEFORE`, `NLS_VIP_DURING`, and `NLS_VIP_AFTER` with `ip -6 addr show dev wan0` output from both endpoint routers. Router-CA lookups are served by a signed test shim; a live Router-CA service is not exercised by this lab.
- At the Prompt 3 checkpoint, lab application traffic used the NLE1 legacy path and was not security evidence. The current Prompt 4 data path is NLE2; see the current-head gate record in `Documentation/TRACEABILITY.md`.
- The CLI command `nls route <prefix> via <router-id>` and `show running-config` exist in `tools/router_cli/commands.py`. Route creation requires a fresh signed directory, an active non-revoked router record, a route prefix within the peer's CA-authorized prefixes, and no overlap with local or configured operator prefixes. `install_tun_routes` continues to skip existing kernel routes.
- NAT traversal remains **NOT VERIFIED**; no NAT scenario is exercised.
- The source-integrity job's previous failure was a manifest path mismatch, not a verified tamper rejection. The workflow now writes a basename-relative manifest from inside `dist/` and checks a tampered file with the same basename in `/tmp`. The source-integrity job passed on the current tested code head; see the latest Actions evidence in `Documentation/TRACEABILITY.md`.
- Prompt 4 work followed this checkpoint; the remaining lifecycle, performance, and independent-review caveats are listed below and in `Documentation/OPEN_QUESTIONS.md`.


- S3/S4 compare only stable RDR identity/authorization fields. status is independently required to be ACTIVE; record_seq is a monotonic freshness value, not an equality field, so a fresh lookup with a higher sequence does not falsely reject a peer. issued_at and valid_until remain freshness checks.
- The source-integrity negative check intentionally modifies a copy of the package and expects sha256sum -c to report a mismatch. The workflow labels that mismatch EXPECTED_NEGATIVE_CHECK; the original package checksum is checked separately and must pass.


## Prompt 4a implementation history — 2026-10-16

The preceding Prompt 2/3 sections are historical records of the state at those
gates; statements there about the data-plane implementation describe the earlier
revision, not the current branch head. Prompt 4a replaces the active data path
with NLE2: fixed 32-byte AAD header, directional AES-256-GCM session keys and
IV prefixes from NLH2, a 64-bit sequence number, and no per-packet RSA key
wrapping. The handshake still uses its existing RSA envelope where required;
that is separate from data-plane packet protection.

## Current Prompt 4 gate evidence — 2026-10-16

The active data path is NLE2: a fixed 32-byte authenticated header, directional
AES-256-GCM session keys and IV prefixes, 64-bit sequence numbers, and no
per-packet RSA wrapping. RSA remains in the handshake envelope where specified;
it is not used to wrap a key for each data packet.

On implementation/test head `efacc12f828c2a67cae781a56f98fd4486267dbf`,
Actions run `38892600029` passed all 12 jobs; ShellCheck run `38892600058`
and CodeQL run `38892600028` passed. Package suites reported 155 passed on
Ubuntu 22.04 and 155 passed, 2 warnings on Ubuntu 24.04. Strict-xfail command
`pytest -q -rx tests/integration/test_nls_v1_spec.py -m integration` reported
26 passed on both OS versions with no xfails. Both six-node labs passed,
including TCP/UDP/return path, route-table assertions and WAN-node pcap test.
The measured end-to-end 100 Mbit/s target is not met; current run output and
method are recorded in `Documentation/NLE2_PERFORMANCE.md`.

The startup route regression permits only the kernel-generated
`fe80::/64 dev nls0 proto kernel metric 256 pref medium` route created when
the TUN interface appears. It asserts no removed routes and no other added
routes. The CA-driven route snapshot and operator-route positive control are
also emitted by the six-node lab. NAT traversal remains **NOT VERIFIED**.
Independent security review is still required; CI success is not a security
certification.


## 2026-10-24 — SourceToken specification reconciliation

- The Core copy of `docs/nls/MASTER_SPEC.md` described AES-256 single-block encryption for SourceToken derivation, while the NetOS master specification and active `nls/source_token.py` implementation define HKDF-SHA-256 followed by HMAC-SHA-256 over a domain-separated message and the sender's packed IPv6 `originalIP`.
- The minimal safe resolution is to synchronize the Core specification to the already-implemented NetOS construction. This is a specification correction only; it does not change runtime behavior or introduce a new cryptographic primitive.
- SourceToken is a pseudonymous routing identifier, not reversible encryption. Inner-packet confidentiality is provided by the separately specified AES-256-GCM payload protection.
- This reconciliation establishes implementation/spec consistency, not independent cryptographic approval. Any future derivation change must be explicitly versioned and tested across both peers; silent algorithm substitution is prohibited.
