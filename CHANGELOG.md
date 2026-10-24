## Unreleased — NLD2 metadata protection modes (2026-10-24)

- Implemented versioned NLD2 framing, strict `source-only` (Mode A) and `source-destination` (Mode B) policy enforcement, authenticated visible-destination verification, and mode-specific MTU accounting.
- Added unit and daemon forwarding tests, IPv4/IPv6 visible-destination tests, legacy-format rejection, replay-state safety, and real WAN-capture integration for both modes.
- Exact-head unit and lab gates passed on Ubuntu 22.04 and 24.04 on the preceding implementation commit. Final security scans and CI after the current hardening changes are pending.

## Unreleased — SourceToken specification reconciliation (2026-10-24)

- Core's cross-repository integration suite compares the normative SourceToken wire-format and metadata-mode sections, while allowing repository-specific audit material elsewhere in the master specs.
- Synchronized the Core master specification with the existing NetOS HMAC-SHA-256 SourceToken derivation, removing the conflicting AES block-encryption description.
- No runtime code or wire behavior changed. Cross-repository specification consistency must be rechecked by the dedicated validation gate.

## Unreleased — Prompt 3 gate fixes (CI green)

- Captured the six-node NLH2/vIP lab stdout with pytest `-s` and retained it as a run-specific Actions artifact.
- Added a separately named log-canary test step and made the intentional SHA-256 tamper rejection explicit in source-integrity output.
- Corrected the S3/S4 contract to compare stable RDR fields only; status, record_seq, issued_at and valid_until remain independent state/freshness checks.
- Fixed test settings compatibility for omitted optional cache paths and added sequence-advance coverage.

# Changelog

## Unreleased — Prompt 2

- Added Router-CA client verification for canonical-CBOR signed RDRs and directory bundles, including signed nonce checks, expiry, rollback rejection and atomic verified-cache persistence.
- Added `trust_mode: ca|offline` and `stale_grace_seconds: 0` configuration.
- Added `nlsxnetos router-ca import FILE` for signed offline bundles.
- Replaced the unsigned YAML Router-CA trust path with a signature-verified directory cache.
- Exposed directory freshness and certificate revocation accessors for later daemon integration.

- Converted the Prompt 1 forged-CA-response and CA-unreachable strict-xfail cases into passing client-verification tests; 21 handshake/data-plane strict xfails remain assigned to later prompts.
- Prompt 2 router/client gate passed in CI run 38862159980 on Ubuntu 22.04 and 24.04.

- Implementation commit `9ece89dab0aed7e26af26f376f52c3568d7ed191` passed Actions run 38881019480: 137 tests passed on both Ubuntu 22.04 and 24.04, the six-node NLH2/vIP lab passed, and the strict-xfail matrix reported 3 passed / 7 xfailed. The traceability-only follow-up is awaiting its own exact-head rerun.

- Exact-head Actions run 38881435144 on `68825fd3f3ad50d758adacd4c1147991646f5069` passed: Ubuntu 22.04 `137 passed in 68.50s`; Ubuntu 24.04 `137 passed, 2 warnings in 31.78s`; six-node lab `1 passed in 17.31s`; strict-xfail scaffold `3 passed, 7 xfailed in 1.34s`; named canary passed on both OS versions; source integrity verified the original checksum and explicitly rejected the tampered copy.
