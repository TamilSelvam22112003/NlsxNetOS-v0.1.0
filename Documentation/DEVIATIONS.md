# Deviations — Prompt 2

- The verified directory cache is JSON-serialized for atomic persistence, but every trust-bearing envelope is re-verified over canonical CBOR with the out-of-band pinned Ed25519 control identity before use. The cache itself is not a trust anchor.
- Offline import rejects expired bundles and directory-sequence rollback. Offline mode is explicitly degraded because it cannot learn a new revocation until an operator imports a newer bundle.
- The directory-sync implementation consumes a full signed snapshot rather than incremental deltas.
- Daemon revocation teardown is intentionally not wired in Prompt 2; `is_revoked` and `directory_freshness` are exposed for the handshake/data-plane gates in prompts 3–4.
- The previous unsigned YAML trust store is read-only/ignored as a trust source. Existing add/remove entry commands now fail closed and direct administrators to Router-CA registration/revocation and signed bundle import.
- Prompt 1 integration fixtures that formerly seeded unsigned YAML were migrated to generated, pinned-key signed directory bundles. This test change is intentional because accepting the old fixture format would violate the signed-directory requirement.
