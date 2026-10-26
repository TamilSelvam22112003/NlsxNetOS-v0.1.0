# NLS Implementation Conformance Map

**Status:** audit artifact; not a protocol freeze or production-readiness certification.  
**Audit baseline:** NlsxNetOS `work/ospfv3-full-nls-lifecycle` at `2c3a711d8d1c40812311bac51868952aac56d631`; NexOS Core `feat/nls-v1` at `330fd7cfefe6c2a1408a3a12448c31331796052e`.  
**Scope:** function-level runtime map and evidence gaps for the handshake, directory/trust lifecycle, data plane and routing integration.

## 1. Runtime call path

### 1.1 UDP ingress and handshake demultiplexing

1. `nls/daemon.py:NLSDaemon._dispatch_datagram`
   - Recognizes known SourceToken outer source addresses and dispatches those packets to `_handle_data`.
   - Dispatches datagrams beginning with `NLH2` to `self.v2.handle_packet(...)`.
   - Unknown formats are dropped. The legacy `NLSH` INIT/RESPONSE handlers explicitly reject legacy handshakes.
2. `nls/v2_runtime.py:HandshakeV2.handle_packet`
   - Applies source/interface rate limiting.
   - Parses the NLH2 envelope and dispatches M1, M2, M3 or M4.
   - Out-of-order or malformed messages are dropped.
3. `HandshakeV2._handle_m1`, `_handle_m2`, `_handle_m3`, `_handle_m4`
   - Decode sealed messages and check message state.
   - Validate timestamps, peer identity and current Router Directory Record (RDR) data at the applicable stages.
   - Check certificate/RDR bindings, signatures, transcript, endpoint assertions and key confirmation as required by each stage.
   - Maintain pending-handshake state with timeout and replay handling.

**Finding:** The apparent `NLSH` version-1 code in `nls/handshake.py` is not evidence that the live daemon uses that format. The daemon explicitly rejects legacy `NLSH`; its dispatch sends `NLH2` to `nls/v2_runtime.py`. Keep this distinction explicit in documentation and tests.

### 1.2 Router-CA and directory trust

Router-side entry points in `nls/ca_client.py` include:

- `_open_channel` — establishes the authenticated control channel.
- `_validate_rdr_v2` — validates the RDR field contract.
- `_verify_directory_envelope` — verifies signed directory envelopes.
- `_validate_lookup_response` / `lookup` — validates lookup responses and performs lookup.
- `directory_sync`, `is_revoked`, `directory_freshness`, `heartbeat_freshness` — expose synchronized directory, revocation and freshness state.
- `cached_record` / `lookup_envelope` — provide verified peer records/envelopes to callers.

Core-side implementation files are `src/nls_nexos_core/control.py`, `control_protocol.py`, `api.py`, `database.py`, `directory.py`, and `ca.py`. The registry schema defines router status and a unique `original_ip`; signed RDR operations are implemented in `directory.py`.

**Verification still required:** prove that every route to a peer record uses the signature-verified path; test stale bundle, rollback, revocation, disabled/expired router, record-sequence rollback, and lookup authorization against both the Core server and router client.

### 1.3 vIP verification to Trust Table authorization

1. `HandshakeV2._handle_m1` and `_handle_m2` stage identity candidates through `VIPVerificationTable.stage`.
2. `VIPVerificationTable.verify` requires both Router-CA record verification and destination-router signature verification, plus matching identity-record fields, before returning a `VERIFIED` row.
3. In the M3/M4 completion paths, the runtime calls `vip_verification.verify(...)`, then `trust_table.record_verified_vip(...)`, then checks `trust_table.is_trusted(sid)` before activation.
4. `TrustTable.record_verified_vip` requires status `VERIFIED` and explicit true values for Router-CA record, destination router, certificate, public key, original IP and record-sequence checks.
5. `HandshakeV2._activate_session` independently checks `vip_verification.is_verified(sid)`, registers the SourceToken-to-session mapping, publishes authenticated LSDB metadata, and then publishes the session to the daemon. It removes the short-lived vIP verification row after successful publication.
6. `HandshakeV2.expire` aborts timed-out pending handshakes, expires vIP state, expires Trust Table rows on a bounded 500 ms cadence, and tears down sessions whose trust leases expire.

**Important distinction:** the Trust Table is the persistent authorization record; the vIP table is short-lived verification staging. Neither should be treated as an operator routing table. Runtime comments and tests explicitly state that RDR/CA metadata must not install kernel routes.

**Concurrency note:** `TrustTable._state_lock` uses a thread reentrant lock plus a per-state-file `flock` for process-level read/modify/write serialization. `VIPVerificationTable` currently uses a process-local threading lock and atomic replacement, not the same per-file process lock. Its router-ID-specific file path reduces cross-router collisions, but same-router multi-process writers remain a separate condition to assess.

### 1.4 Protected data-plane ingress

1. `NLSDaemon._dispatch_datagram` matches the outer SourceToken to a session.
2. `NLSDaemon._handle_data` requires an established/overlap session, matching receive token and `NLD2` format.
3. It checks replay eligibility before decrypting, calls `open_source_token_payload` with the receive key, IV prefix, outer source and expected local original IP, and commits the replay counter only after AEAD authentication and IP validation.
4. It checks the message type and configured inner-source/destination prefix policies, then writes the authenticated inner packet to the TUN device.
5. Any exception causes a drop and a reason-coded log; legacy NLE2 data is not accepted as a fallback.

### 1.5 Protected data-plane egress and routing selection

- `NLSDaemon._send_payload` rejects IPv6 multicast on the NLS TUN path and selects a peer using explicit operator route configuration.
- `_peer_for_destination` documents that RDR prefixes are authorization metadata, not routing instructions.
- SourceToken packet construction is in `nls/source_token.py:seal_source_token_payload`; source-token socket creation and binding are in `open_source_token_socket`.
- The actual FRR/OSPFv3 invariance tests are in `tests/integration/test_ospfv3_nls_invariance.py`; the six-node lifecycle and ten-router IPv6 tests exercise broader integration.

## 2. Evidence inventory

| Property | Implementation evidence | Test evidence present in audited tree | Assessment |
|---|---|---|---|
| NLH2-only wire dispatch | `daemon.py:_dispatch_datagram`; `v2_runtime.py:handle_packet` | `tests/security/test_nlh2_acceptance.py` includes legacy rejection, malformed and out-of-order cases | Implemented; maintain as a hard compatibility boundary |
| Certificate and RDR binding | `v2_runtime.py:_certificate`, `_validate_record`, `_record_envelope`, M1–M4 handlers | Wrong chain, expiry, field mismatch, stale lookup, non-ACTIVE and forged envelope tests | Substantial negative-test coverage; broader independent review still needed |
| Anti-amplification / early peer screening | M1 handling and padding path in `v2_runtime.py` | Tests for wrong-key M1 screening and M1 padding budget | Test-backed at unit level |
| VIP staging / verification | `vip_table.py:stage/verify/is_verified` | `test_nlh2_acceptance.py`, `test_vip_table.py`, `test_vip_table_cross_verification.py` | Test-backed; assess multi-process table writers |
| Trust Table concurrency and lifecycle | `trust_table.py:_state_lock/record_verified_vip/expire/remove` | `tests/security/test_trust_table_lifecycle.py`: tampering, external replacement, expiry, restart, threads and processes | Substantial regression coverage |
| Replay protection | `daemon.py:_handle_data`; `source_token.py:open_source_token_payload` | Replay/security tests in unit and integration suites | Verify that replay state is committed only after authentication; current data path does this |
| Inner packet authorization | `_handle_data`, source/destination prefix validators | Source-token and prefix tests | Config-dependent; test enabled and disabled policy behavior explicitly |
| CA metadata cannot create routes | `_peer_for_destination`; `_activate_session` LSDB publication comments | `test_nlh2_acceptance.py` includes route-injection regression tests; OSPFv3 invariance integration | Test-backed in lab; deployment routing cases remain |
| Core/router protocol compatibility | Router `ca_client.py`; Core `control_protocol.py` | `tests/integration/test_nls_control_cross_repo.py` in Core | Must run against exact pinned Core SHA for each proposed router head |
| Revocation and process restart | CA client cache, heartbeat and revocation functions; runtime session teardown | Existing revocation, stale-heartbeat, startup-cleanup and lifecycle tests | Verify end-to-end with an established data session and during Core unavailability |

## 3.1 Confirmed specification precedence gap

The audited lifecycle branch's `docs/nls/MASTER_SPEC.md` blob `26e174f0b4c1d662113c26106f9e310d2946314e` still contains normative statements that M1/M3 use the derived vIP as outer source and M2/M4 use it as outer destination (for example, base sections near lines 47, 123–132, and the consolidated invariant near line 466). However, the same repository already has a separate docs-only Stage 7 branch, `docs/stage7-vip-bootstrap-reachability` at `051c5ca2b35204762a621f678be48b50bd420ffd`, whose MASTER_SPEC adds an explicit precedence rule: authenticated routable WAN locators are used for NLH2 outer headers; derived `vip` stays in the signed/sealed handshake context and is not an outer address, interface address, or FIB route.

The active runtime on the audited lifecycle head matches the Stage 7 locator model:
- `HandshakeV2.start` derives a vIP for handshake context but sends M1 to the peer's authoritative endpoint using `owner.sock.sendto(packet, (host, port))`; its comment says the outer source is the authoritative WAN locator.
- `_handle_m1` checks the observed outer source against the authoritative RDR endpoint.
- `_handle_m3` similarly validates the sender's observed endpoint against fresh RDR data.
- M2/M3 transmission uses authenticated endpoints; the M1 vIP remains an inner signed/sealed field.
- Post-M4 data-plane outer source is the directional SourceToken, not the retired handshake vIP.

**Disposition:** this is a documentation-baseline/precedence defect, not evidence that the active locator behavior should be changed back to vIP outer addressing. Do not change runtime behavior to match the older conflicting examples. The docs-only Stage 7 amendment in router PR #53 is the existing intended resolution and must be reviewed/accepted into the normative baseline before the implementation can be declared specification-conformant. Until then, Stage 3 is BLOCKED on an unambiguous normative spec.

## 4. Specification conformance questions to close before changing protocol code

1. **Wire-format authority:** document that NLH2 in `v2_runtime.py` is the active handshake and that `NLSH` in `handshake.py` is legacy/rejected; decide whether legacy helpers are still needed by any non-runtime caller.
2. **vIP semantics:** reconcile the spec's bootstrap-vIP language with the current authenticated-WAN-locator/SourceToken implementation. Do not silently conflate handshake identity staging, outer locator reachability and data-plane SourceTokens.
3. **Trust lease authority:** define whether `TrustTable.is_trusted` must be rechecked at each packet or whether the session teardown invariant is sufficient; test teardown races with in-flight packets.
4. **VIP table process safety:** decide whether single-daemon-per-router is a documented invariant or whether VIP table read/modify/write needs the same advisory-lock discipline as Trust Table.
5. **Record freshness and revocation:** state exact behavior when directory freshness expires, a peer record sequence advances, a certificate is revoked, or Core becomes unreachable while a session is active.
6. **Routing boundaries:** specify which information can update the LSDB, which can select a peer, and which is forbidden from installing kernel/FRR routes.
7. **Cross-repo compatibility:** pin the exact Core commit used by each integration test; avoid tests that silently use a moving branch head.

## 5. Recommended gate sequence

- **Gate A — Spec diff only:** compare the normative NLH2 and SourceToken requirements with the audited active call paths; document ambiguities in `OPEN_QUESTIONS.md` and deviations in `DEVIATIONS.md`. No protocol behavior changes yet.
- **Gate B — Focused regressions:** add only tests that fail for a clearly demonstrated requirement gap, starting with Trust Table expiry/revocation races, VIP table same-router multi-process writers, and established-session revocation behavior.
- **Gate C — Cross-repo and lab CI:** run the Core control integration, six-node lifecycle, ten-router IPv6, FRR/OSPFv3 invariance, package/security jobs and evidence validation on the exact final commit.
- **Gate D — Deployment gap report:** separately record NAT/firewall/uRPF, asymmetric WAN routing, real PMTU/fragmentation, restart/recovery and real-network tests.

## 6. Limits of this audit

This is a static source-and-test-tree conformance map. It does not claim that tests were executed during this audit, does not replace cryptographic review, and does not certify production readiness. The recorded prior CI run applies only to its recorded commit. Re-run all required gates after any source change.
