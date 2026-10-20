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
| A-01 | `nls/handshake.py` retains legacy `NLSH`/JSON helpers, but the active daemon runtime imports the v2 NLH2 APIs (`open_v2_message`, `encode_v2_message`, `sign_v2`) from that module. The legacy helpers alone do not prove the active handshake uses NLSH. | `nls/handshake.py`; `nls/v2_runtime.py` imports and calls the v2 APIs | PARTIAL — active path uses NLH2; verify every wire field against the amendments |
| A-02 | The active `HandshakeV2` path does perform signed-RDR/cache validation and fresh lookups at M2/M3 stages, but its field set and vIP lifecycle still need comparison against the latest amendments. | `nls/v2_runtime.py`: `_handle_m1`, `_handle_m2`, `_handle_m3`, `_handle_m4`, `_record_envelope` | PARTIAL — amendment parity not yet proven |
| A-03 | ReplayWindow's API explicitly requires callers to call `can_accept()` before authentication and `mark()` only after AEAD authentication. The window itself does not perform locking; caller-level concurrency safety must be checked. | `nls/replay.py`: module docstring, `can_accept()`, `mark()` | CONFIRMED API contract; call-site safety NOT VERIFIED |
| A-04 | NetOS declares `cbor2==5.9.0` and `cryptography>=42.0`; dependency pins differ from NexOS Core's lower bound for cryptography. Compatibility should be tested against the supported Python/Ubuntu matrix. | `pyproject.toml` in each repository | CONFIRMED |
| A-05 | The README describes importing a signed directory bundle in offline/operator workflows, while the master spec's default trust mode requires live authenticated lookups and zero stale grace. These can coexist only if trust-mode semantics are enforced consistently by the implementation. | `README.md`; `docs/nls/MASTER_SPEC.md` | NEEDS CALL-SITE VERIFICATION |

## Known CI evidence to retain

The repository's `docs/nls/CI_BASELINE_ISSUES.md` records sampled NetOS six-node failures, including `NLS_DATA_SESSION_INVALID`, `iperf3` timeout, Router-CA rollback-mark bundle-expiry mismatch, and `_log_drop` TypeError. It also records successful sampled ten-router IPv6 and Ubuntu 22.04 package jobs at the listed revision. Those historical results are not current-head test results.

## Additional confirmed amendment gaps

- The active `nls/v2_runtime.py` bootstrap allocates a random temporary address through `VIPManager`; the master-spec hybrid amendment instead specifies a deterministic SHA-512-derived candidate with fresh `vip_nonce`, `time_bucket`, and policy-v1 validation. This is an implementation/spec discrepancy requiring an explicit migration.
- The active `nls/encapsulation.py` still emits the 32-byte NLE2 header. The latest master-spec amendment explicitly replaces that data header with SourceToken demultiplexing and a `counter || AEAD(ciphertext) || tag` payload. SourceToken is therefore **specified but not yet implemented** in the active data plane.
- The initial six-node `iperf3` timeout occurs before the revocation check, so revocation ordering was not the root cause. Later runs reached the final revocation check after the traffic/rekey/MTU/packet-capture stages, then exposed a test-metric bug: the test measured the full six-second stability observation rather than the time to first teardown. The test now records teardown latency separately while continuing to observe for the full heartbeat bound. NetOS also now serializes Router-CA cache/rollback-mark writers and cold readers with a sidecar file lock; the latest CI rerun is needed to confirm the complete fix.

## Required next checks

1. Verify branch head and tags for both repositories and retrieve complete CI job evidence.
2. Trace every handshake stage and data-plane call site against the authoritative spec, including replay-window commit ordering and locking.
3. Verify Router-CA revocation/freshness checks at the point where data sessions are accepted.
4. Add regression tests before changing behavior; preserve test thresholds and timeouts.
5. Do not report a pass until the command or CI run actually completes and its output is captured.

## Status

Audit documentation was committed, and the six-node test-order defect has since been corrected in a separate commit. The active SourceToken data-plane migration remains outstanding. Local checkout tests were not run; GitHub Actions is the available executable validation path.