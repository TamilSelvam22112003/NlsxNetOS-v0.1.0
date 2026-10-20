# NLS implementation audit — 2026-10-20

## Scope and evidence

This is an initial repository-first audit on `feat/nls-v1`. It records only facts confirmed from files retrieved during this pass. It is not a security certification or a claim that the full acceptance suite was run.

- Repository: `TamilSelvam22112003/NlsxNetOS-v0.1.0`
- Branch requested by project specification: `feat/nls-v1`
- Retrieved files: `docs/nls/MASTER_SPEC.md`, `nls/handshake.py`, `nls/replay.py`, `nls/ca_client.py`, `README.md`, `pyproject.toml`
- Local checkout, working-tree status, branch head SHA, and test execution are **not verified in this audit**.

## Confirmed implementation/specification discrepancies

| ID | Finding | Evidence | Status |
|---|---|---|---|
| A-01 | The retrieved handshake implementation uses `NLSH` framing and canonical JSON, with a self-contained signature check. This differs from the NLH2 sealed deterministic-CBOR framing specified in the current master spec. | `nls/handshake.py`: `MAGIC=b"NLSH"`, `canonical()`, `encode_message()`, `decode_message()` | CONFIRMED |
| A-02 | The handshake code shown validates the peer's claimed identity public key against the message and verifies its signature, but this excerpt does not demonstrate the spec-required certificate-chain, signed RDR, status, or live Router-CA checks. | `nls/handshake.py`: `verify()`; compare with `docs/nls/MASTER_SPEC.md` authentication and lookup stages | PARTIAL — inspect call sites before final conclusion |
| A-03 | ReplayWindow's API explicitly requires callers to call `can_accept()` before authentication and `mark()` only after AEAD authentication. The window itself does not perform locking; caller-level concurrency safety must be checked. | `nls/replay.py`: module docstring, `can_accept()`, `mark()` | CONFIRMED API contract; call-site safety NOT VERIFIED |
| A-04 | NetOS declares `cbor2==5.9.0` and `cryptography>=42.0`; dependency pins differ from NexOS Core's lower bound for cryptography. Compatibility should be tested against the supported Python/Ubuntu matrix. | `pyproject.toml` in each repository | CONFIRMED |
| A-05 | The README describes importing a signed directory bundle in offline/operator workflows, while the master spec's default trust mode requires live authenticated lookups and zero stale grace. These can coexist only if trust-mode semantics are enforced consistently by the implementation. | `README.md`; `docs/nls/MASTER_SPEC.md` | NEEDS CALL-SITE VERIFICATION |

## Known CI evidence to retain

The repository's `docs/nls/CI_BASELINE_ISSUES.md` records sampled NetOS six-node failures, including `NLS_DATA_SESSION_INVALID`, `iperf3` timeout, Router-CA rollback-mark bundle-expiry mismatch, and `_log_drop` TypeError. It also records successful sampled ten-router IPv6 and Ubuntu 22.04 package jobs at the listed revision. Those historical results are not current-head test results.

## Required next checks

1. Verify branch head and tags for both repositories and retrieve complete CI job evidence.
2. Trace every handshake stage and data-plane call site against the authoritative spec, including replay-window commit ordering and locking.
3. Verify Router-CA revocation/freshness checks at the point where data sessions are accepted.
4. Add regression tests before changing behavior; preserve test thresholds and timeouts.
5. Do not report a pass until the command or CI run actually completes and its output is captured.

## Status

Phase 1 is **PARTIALLY VERIFIED**. No product code was changed by this audit. No tests were run in a local checkout.