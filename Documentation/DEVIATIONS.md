# Deviations — Prompt 2 and Prompt 3 (Prompt 3 gate passed)

- The verified directory cache is JSON-serialized for atomic persistence, but every trust-bearing envelope is re-verified over canonical CBOR with the out-of-band pinned Ed25519 control identity before use. The cache itself is not a trust anchor.
- Offline import rejects expired bundles and directory-sequence rollback. Offline mode is explicitly degraded because it cannot learn a new revocation until an operator imports a newer bundle.
- The directory-sync implementation consumes a full signed snapshot rather than incremental deltas.
- Daemon revocation teardown is intentionally not wired in Prompt 2; `is_revoked` and `directory_freshness` are exposed for the handshake/data-plane gates in prompts 3–4.
- The previous unsigned YAML trust store is read-only/ignored as a trust source. Existing add/remove entry commands now fail closed and direct administrators to Router-CA registration/revocation and signed bundle import.
- Prompt 1 integration fixtures that formerly seeded unsigned YAML were migrated to generated, pinned-key signed directory bundles. This test change is intentional because accepting the old fixture format would violate the signed-directory requirement.


## Prompt 3 implementation notes — gate passed for implementation commit 471694a7946f

- The active handshake dispatch accepts NLH2 messages only. The legacy NLSH/JSON helper functions remain in `nls/handshake.py` for compatibility with old unit consumers, but the daemon's UDP receive loop does not dispatch legacy INIT/RESPONSE messages; legacy NLE1 data encapsulation remains intentionally present until Prompt 4.
- Existing `tests/unit/test_nls_handshake.py` was replaced with NLH2 tests for sealed message round-trip, recipient-key rejection, signature/transcript tampering, and strict unknown/missing-field rejection. Additional handshake acceptance coverage lives in `tests/security/test_nlh2_acceptance.py`.
- The vIP state file now retains `last_assigned` and `last_released` audit markers to make short-lived bootstrap addresses verifiable in namespace tests even when the M1–M4 exchange completes faster than an observer polling interval. These markers contain addresses only, not keys, tokens, or packet plaintext.
- The 10-router lab requires explicit return routes for both endpoint vIP pools. NAT traversal is not implemented or verified; deployments behind NAT remain unsupported/untested.
- The NLH2 handshake establishes session-derived directional keys, but the data plane still uses legacy NLE1 per-packet RSA wrapping in this prompt. This branch is experimental, is not independently reviewed, and must not be treated as secure or production-ready until Prompt 4 replaces that data path and the resulting implementation is independently assessed.
- Prompt 3 acceptance gate evidence is recorded in Documentation/TRACEABILITY.md and GitHub Actions run 38874400473. Ubuntu 22.04/24.04 suites, four-node vIP/handshake/forwarding lab, ten-router IPv6 lab, fresh-install jobs, dependency audit, and source-integrity checks passed for implementation commit 471694a7946fa6c7ed98fa9f90aead09c9b43e98.
