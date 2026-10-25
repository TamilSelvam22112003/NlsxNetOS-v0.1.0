# NLS requirement traceability — 2026-10-25 review

Target branch: `feat/nls-v1` in both repositories. This table records the current evidence boundary; it is not a declaration that all requirements have passed.

| Requirement | Primary implementation | Required evidence | Status |
|---|---|---|---|
| R1 — Router certificate and RDR binding | `nls/ca_client.py:_validate_rdr_v2`; `nls/v2_runtime.py:_certificate` | Valid, wrong-root, expired, revoked and key-mismatch tests | Partially implemented; strict unknown-field rejection remains open |
| R2 — vIP ownership/lifecycle | `nls/vip.py:VIPManager`; `nls/v2_runtime.py:HandshakeV2` | Assignment, expiry, crash cleanup, collision and post-switch rejection | Random allocation/cleanup implemented; amended deterministic derivation not implemented |
| R3 — M1/M2 sealed handshake | `nls/handshake.py`; `nls/v2_runtime.py:_handle_m1/_handle_m2` | M1 schema, vIP derivation, anti-amplification, source binding, malformed messages | Partially implemented; amended M1 fields/derivation not conformant |
| R4 — M3/M4 mutual trust and key confirmation | `nls/v2_runtime.py:_handle_m3/_handle_m4`; `nls/key_schedule.py` | S3/S4 mismatch, transcript tamper, confirmation failure, loss/retry | Core checks implemented; M4-loss recovery not verified |
| R5 — Endpoint switch and vIP retirement | `nls/v2_runtime.py`; `nls/vip.py` | Temporary source used only during handshake; retired-vIP traffic rejected | Partially implemented; loss and restart cases need additional validation |
| R6 — Signed, nonce-bound Router-CA lookup | Core `api.py/control.py/directory.py`; NetOS `nls/ca_client.py` | Forged signature, nonce mismatch, stale lookup and unauthorized caller | CI/test evidence exists; exact-head amended protocol interoperability not verified |
| R7 — Freshness, sequence and revocation | `nls/ca_client.py`; `nls/v2_runtime.py`; `nls/daemon.py` | Rollback, expired bundle, active-session revocation and restart | Partially implemented; active-session lifecycle tests required |
| R8 — Session-key schedule | `nls/key_schedule.py` | Deterministic vectors, all-zero DH rejection, directional separation | Implemented primitives; independent cryptographic review not performed |
| R9 — Authenticated data plane | `nls/source_token.py`; `nls/daemon.py:_handle_data` | Tamper, wrong key, mode mismatch, replay and packet capture | Active SourceToken AEAD exists; NLD2 framing/mode contract not implemented on this branch |
| R10 — Metadata policy | `nls/source_token.py`; configuration | Source-only and source-destination leakage tests; exact NLD2 framing | Not implemented on reviewed `feat/nls-v1` branch |
| R11 — Routing semantics | `nls/routing.py`; `nls/lsdb.py`; FRRouting integration | CA metadata does not create routes; actual OSPF/OSPFv3 LSA behavior; BGP/RIP if claimed | Operator-route boundary tested; actual LSA propagation and BGP/RIP interoperability not verified |
| R12 — Replay policy | `nls/replay.py:ReplayWindow`; `nls/daemon.py:_handle_data` | Failed authentication does not advance window; duplicate/out-of-window packets rejected | Existing unit/security evidence; exact-head regression retained |
| R13 — Safe audit logs and failure behavior | `nls/v2_runtime.py`; `nls/daemon.py`; Core `control.py` | Canary-secret redaction, stable reason codes, bounded error logs | Partial test evidence; continue exact-head validation |
| R14 — Cross-repository control protocol | NetOS `nls/control_protocol.py`; Core `src/nls_nexos_core/control_protocol.py` | Compatibility test and Core/NetOS control integration on both Ubuntu versions | Passed in reviewed CI run; this does not prove NLH2/NLD2 conformance |

## V1–V11 hypothesis cross-reference

The detailed V1–V11 findings are in `Documentation/nls/IMPLEMENTATION_AUDIT_2026-10-25.md`. Legacy helper code must not be confused with the active NLH2/SourceToken path. The current highest-priority gaps are R2/R3 amended vIP fields, R9/R10 NLD2 framing and metadata mode, strict RDR schema validation, M4-loss recovery, and connection-level resource bounds.

## CI evidence

- NetOS run: https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/40091947203
- Core run: https://github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.0/actions/runs/40091955351

The new strict-xfail NLD2 regression test was committed after the reviewed NetOS base head. Its result is **not verified** until CI completes on the updated branch.
