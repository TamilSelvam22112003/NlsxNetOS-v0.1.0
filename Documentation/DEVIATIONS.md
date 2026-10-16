# Deviations — Prompt 2 and Prompt 3 (Prompt 3 gate NOT ACCEPTED)

- The verified directory cache is JSON-serialized for atomic persistence, but every trust-bearing envelope is re-verified over canonical CBOR with the out-of-band pinned Ed25519 control identity before use. The cache itself is not a trust anchor.
- Offline import rejects expired bundles and directory-sequence rollback. Offline mode is explicitly degraded because it cannot learn a new revocation until an operator imports a newer bundle.
- The directory-sync implementation consumes a full signed snapshot rather than incremental deltas.
- Daemon revocation teardown is intentionally not wired in Prompt 2; `is_revoked` and `directory_freshness` are exposed for the handshake/data-plane gates in prompts 3–4.
- The previous unsigned YAML trust store is read-only/ignored as a trust source. Existing add/remove entry commands now fail closed and direct administrators to Router-CA registration/revocation and signed bundle import.
- Prompt 1 integration fixtures that formerly seeded unsigned YAML were migrated to generated, pinned-key signed directory bundles. This test change is intentional because accepting the old fixture format would violate the signed-directory requirement.


## Prompt 3 implementation notes — current status is pending exact-head verification

- The active handshake dispatch accepts NLH2 messages only. The legacy NLSH/JSON helper functions remain in `nls/handshake.py` for compatibility with old unit consumers, but the daemon's UDP receive loop does not dispatch legacy INIT/RESPONSE messages; legacy NLE1 data encapsulation remains intentionally present until Prompt 4.
- Existing `tests/unit/test_nls_handshake.py` was replaced with NLH2 tests for sealed message round-trip, recipient-key rejection, signature/transcript tampering, and strict unknown/missing-field rejection. Additional handshake acceptance coverage lives in `tests/security/test_nlh2_acceptance.py`.
- The vIP state file now retains `last_assigned` and `last_released` audit markers to make short-lived bootstrap addresses verifiable in namespace tests even when the M1–M4 exchange completes faster than an observer polling interval. These markers contain addresses only, not keys, tokens, or packet plaintext.
- The 10-router lab requires explicit return routes for both endpoint vIP pools. NAT traversal is not implemented or verified; deployments behind NAT remain unsupported/untested.
- The NLH2 handshake establishes session-derived directional keys, but the data plane still uses legacy NLE1 per-packet RSA wrapping in this prompt. This branch is experimental, is not independently reviewed, and must not be treated as secure or production-ready until Prompt 4 replaces that data path and the resulting implementation is independently assessed.
- Historical run 38874400473 passed on implementation commit 471694a7946fa6c7ed98fa9f90aead09c9b43e98, but it predates current branch-head edits. It is not proof that the Prompt 3 gate is accepted. Current exact-head CI and the updated six-node lab output remain unverified.


## Current Prompt 3 follow-up work (not yet gate-passed)

- The signed RDR comparison contract is explicitly defined by `RDR_S3_S4_COMPARE_FIELDS` in `nls/v2_runtime.py`: `router_id`, `ed25519_public_key`, `rsa_encryption_public_key`, `wan_endpoints`, `gateway_ips`, `prefixes`, `certificate_serial`, `status`, and `record_seq`. `issued_at`/`valid_until` are validated as per-lookup freshness metadata (not equality fields); policy fields are separately checked from the signed policy bundle.
- New tests exercise each of the nine RDR field mismatches at both S3 and S4, timestamp bounds, legacy NLSH INIT/RESPONSE rejection, operator route CLI validation, signed bundle import route non-mutation, and directory-sync route non-mutation. These tests are not claimed as passing until exact-head CI is available.
- The integration topology is now six namespaces: client, Router A, intermediate IPv6 WAN, Router B, server, and Router-CA namespace. It emits `NLS_VIP_BEFORE`, `NLS_VIP_DURING`, and `NLS_VIP_AFTER` with `ip -6 addr show dev wan0` output from both endpoint routers. Router-CA lookups are served by a signed test shim; a live Router-CA service is not exercised by this lab.
- The lab's application traffic remains NLE1 legacy-path interoperability after NLH2 M1–M4. The NLE1 path is known forgeable under V3/V8 and is not security evidence.
- The CLI command `nls route <prefix> via <router-id>` and `show running-config` exist in `tools/router_cli/commands.py`. Route creation requires a fresh signed directory, an active non-revoked router record, a route prefix within the peer's CA-authorized prefixes, and no overlap with local or configured operator prefixes. `install_tun_routes` continues to skip existing kernel routes.
- NAT traversal remains **NOT VERIFIED**; no NAT scenario is exercised.
- The source-integrity job's previous failure was a manifest path mismatch, not a verified tamper rejection. The workflow now writes a basename-relative manifest from inside `dist/` and checks a tampered file with the same basename in `/tmp`. Current-head CI must verify this correction.
- No Prompt 4 work has started. NLE1 data-plane hardening, rekey collision handling, and remaining data-plane tests stay out of scope for Prompt 3.


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

Current Prompt 4a gate status: NOT ACCEPTED until exact-head Ubuntu 22.04/24.04
CI, strict-xfail output, netns TCP/UDP tests, route-table isolation checks, and
the WAN-node pcap confidentiality test are all confirmed on the same head. NAT
traversal remains NOT VERIFIED. Performance, rekey, revocation/freshness teardown,
operations, and key zeroization are separate Prompt 4b gate items. The only
remaining strict xfail assigned to Prompt 4b is the reduced-limit rekey lifecycle test.
