# NLS Phase 0 execution report — NetOS

**Reviewed branch:** `feat/nls-v1`  
**Reviewed head:** `10224a1b514f51afdad2f6a63949449f689b7c95`  
**Review date:** 2026-10-20  
**Scope:** Source-level verification of Prompt 1 findings V1–V11 against the current branch. This report is not a runtime test report. No test command or VM/lab was executed in this session.

## Findings against current source

| ID | Current assessment | Evidence at reviewed head | Runtime/test status |
|---|---|---|---|
| V1 — CA revocation state persisted but not consumed | **DISPUTED as stated; verify full integration** | `nls/ca_client.py:_persist_bundle_locked` persists signed directory/revocation state; `is_revoked` reads the verified bundle and checks revoked serials and record status/expiry. `nls/daemon.py:_refresh_session_trust` tears down sessions when trust freshness is lost. | Source inspected; no runtime revocation test executed in this session. |
| V2 — Handshake uses self-signed JSON claim rather than CA | **PARTIAL / legacy-code risk** | `nls/handshake.py:new_init` is the legacy NLSH/JSON implementation. `nls/daemon.py:_handle_init` and `_handle_response` explicitly reject legacy NLSH. The active dispatch is `nls/v2_runtime.py:HandshakeV2.handle_packet`, using NLH2 and signed directory/RDR validation. | Source inspected; no handshake integration test executed in this session. |
| V3 — Derived session keys are not used for data | **DISPUTED; current code uses them** | `nls/daemon.py:Session` carries directional `send_key`/`recv_key`; `_send_payload` uses `seal_ip_packet`; `_handle_data` calls `open_ip_packet` with `recv_key`. `nls/encapsulation.py` uses AES-256-GCM NLE2. | Source inspected; no packet-forwarding test executed in this session. |
| V4 — vIP is only a string | **DISPUTED; address lifecycle exists** | `nls/vip.py:VIPManager.allocate` assigns a random /128 address, `bind_socket` binds a UDP socket to it, and `release` removes it. `nls/v2_runtime.py` owns vIP sockets and tracks retired vIPs. | Source inspected; no live interface/packet-capture test executed in this session. |
| V5 — Handshake is cleartext signed JSON | **PARTIAL / legacy-code risk** | Legacy JSON encoding remains in `nls/handshake.py`, but daemon handlers reject the legacy format. Active handshake implementation is `nls/v2_runtime.py` with NLH2 sealed messages. | Source inspected; no wire-capture test executed in this session. |
| V6 — Endpoint equality blocks NAT and WAN role is required | **NOT FULLY VERIFIED** | Configuration and peer endpoint checks exist across `nls/v2_runtime.py` and `nls/config.py`; this review did not establish the complete NAT behavior matrix. | NAT traversal is not verified. |
| V7 — Forged high sequence poisons ReplayWindow | **Mitigation present; regression result not verified here** | `nls/daemon.py:_handle_data` calls `recv_replay.can_accept(sequence)`, authenticates via `open_ip_packet`, then calls `recv_replay.mark(sequence)`. `nls/replay.py` documents that marking must occur only after authentication. | Test execution not performed in this session. |
| V8 — RSA public key plus clear session metadata opens a data packet | **DISPUTED for active NLE2 path** | `nls/encapsulation.py:open_ip_packet` requires a 32-byte session key, derives the nonce from the directional IV prefix and sequence, authenticates the header with AES-GCM, and rejects an invalid tag. RSA is described in `nls/daemon.py` as handshake-envelope-only. | Negative-test execution not performed in this session. |
| V9 — Per-packet RSA-OAEP unwrap benchmark | **OBSOLETE for active data path** | `tests/benchmarks/benchmark_nle2_session_keys.py` benchmarks NLE2 AES-GCM session-key seal/open. The active data path does not wrap a new RSA key per packet. | No benchmark executed in this session; no new throughput claim is made. |
| V10 — Any INIT failure blocks a peer for 60 seconds | **Not confirmed in current implementation** | `nls/v2_runtime.py:HandshakeV2` has source-rate limiting, bounded pending-handshake state and structured drop reasons. This source inspection did not find the alleged fixed 60-second failure lockout. | Targeted spoofed-INIT test not executed in this session. |
| V11 — CA metadata creates kernel routes | **No evidence of CA-driven route installation in inspected path** | `nls/daemon.py` initializes `self.peers` from configured peers and calls `install_tun_routes(list(self.peers.values()), self.tun.name)`; CA lookup/directory code is separate. | Route-table non-mutation test not executed in this session. |

## Important qualification

The earlier `Documentation/PHASE0_INVENTORY.md` refers to an older review baseline and must not be treated as evidence for this branch head without revalidation. The branch contains later NLH2/NLE2 code, but source inspection alone does not prove successful runtime behavior.

## Gate result

**PARTIAL — source audit updated; runtime gate not passed.**

- Files changed in this repository by this report: `Documentation/PHASE0_EXECUTION_REPORT.md`.
- Tests executed: none in this session; no test output is claimed.
- Remaining gaps: run focused replay-poisoning, NLE2 key/forgery rejection, INIT rate-limit, CA revocation/session teardown, vIP lifecycle, and route-table non-mutation tests at the exact head; run the relevant CI jobs and record their full conclusions.
- Ready for prompt 2: **no** — Prompt 1's required test execution/evidence has not been established in this session.
