# NLS v1 traceability — Prompt 3 seven-fix gate evidence

Prompt 1, Prompt 2, and Prompt 3 gates are accepted. Prompt 4a implementation is in progress on `feat/nls-v1`; the NLE2 data path and initial security tests have been committed, but the Prompt 4a gate is NOT YET ACCEPTED. Exact-head Ubuntu 22.04/24.04 CI, end-to-end TCP/UDP results, performance measurements, route-table isolation evidence, and the remaining operational lifecycle work must be verified before acceptance.

| Requirement | Planned implementation file/function | Planned test | Status |
|---|---|---|---|
| R1 certificate chain/router ID/pinned root/active RDR | nls/ca_client.py:_verify_directory_envelope/lookup/directory_sync; nls/v2_runtime.py:_certificate | tests/security/test_ca_directory.py; NLH2 acceptance tests; cross-repo lookup | PASS — signed directory and active handshake admission |
| R2 random /128 assigned for 10 s | nls/vip.py:VIPManager; nls/v2_runtime.py:start/cleanup | `test_vip_expiry_removes_address_and_clears_ownership`; six-node NLH2 lab snapshots | PASS for this scope — named test passed; run 38881019480 logs/artifact show the vIP only during bootstrap |
| R3 encrypted signed M1 | nls/handshake.py:encode_v2_message/open_v2_message; nls/seal.py; nls/v2_runtime.py | `test_wrong_key_m1_is_screened_before_allocating_pending_state`; `test_m1_padding_covers_maximum_m2_amplification_budget`; protocol fuzz tests | PASS for Prompt 3 scope — named security tests and both OS suites passed on code SHA `9ece89d` |
| R4 encrypted M2 with RDR/gateway/suite/DH | nls/handshake.py strict M2 schema; nls/v2_runtime.py:_handle_m1/_handle_m2 | `test_sa_downgrade_rejected`; strict schema tests; six-node M1–M4 lab | PASS for Prompt 3 scope — handshake lab and schema/policy tests passed |
| R5 endpoint switch/vIP retirement | nls/v2_runtime.py:_handle_m4/close/expire; nls/vip.py:release | `test_retired_vip_data_packet_is_dropped_with_reason_code`; six-node before/during/after snapshots | PASS for this scope — retired-vIP test passed and `NLS_VIP_AFTER` showed no bootstrap vIP on either WAN interface |
| R6 S3 live lookup/M2 comparison | nls/v2_runtime.py:_handle_m2; nls/ca_client.py:lookup | `test_each_rdr_contract_field_mismatch_rejected_at_s3_and_s4` (S3); `test_revoked_router_rejected_s3_s4`; `test_handshake_fails_closed_when_ca_is_unreachable`; `test_newer_record_seq_is_freshness_not_identity_mismatch` | PASS for Prompt 3 scope — all named tests passed on code SHA `9ece89d` |
| R7 S4 M3/RDR check/M4 | nls/v2_runtime.py:_handle_m3; nls/ca_client.py:lookup | `test_each_rdr_contract_field_mismatch_rejected_at_s3_and_s4` (S4); `test_revoked_router_rejected_s3_s4`; `test_forged_ca_lookup_envelope_is_rejected` | PASS for Prompt 3 scope — all named tests passed on code SHA `9ece89d` |
| R8 transcript-bound X25519/HKDF and directional IV prefixes | nls/key_schedule.py:derive_session_keys; nls/v2_runtime.py:_session | key-schedule vectors, wrong-direction packets | Directional key/IV wiring implemented; exact-head Prompt 4a CI pending |
| R9 NLE2 authenticated encapsulation | nls/encapsulation.py:seal_ip_packet/open_ip_packet | header/ciphertext tamper, strict lengths, wrong session/direction, pcap | NLE2 32-byte AAD header and AES-256-GCM implemented; pcap proof deferred to Prompt 5 if WAN capture cannot be completed in the lab |
| R10 sender authentication/tamper | nls/encapsulation.py:open_data; daemon data path | forgery/tamper | not started |
| R11 inner-source authorization/forwarding | nls/daemon.py:_handle_data; nls/routing.py | end-to-end/unauthorized source | not started |
| R12 128-window after AEAD | nls/replay.py:ReplayWindow | replay/out-of-window/poisoning | not started |
| R13 stable reason codes and safe structured logs | nls/daemon.py:_log_drop/_handle_data | log-canary, malformed/tampered packet reason-code tests | PARTIAL — structured reason codes are implemented; exact-head data-plane canary and wire-silence checks pending |
| R14 enrollment/revocation/signed RDR lookup | nls/ca_client.py:enroll/lookup/directory_sync/is_revoked/directory_freshness; security/trust/router_ca/store.py:import_bundle | tests/security/test_ca_directory.py; cross-repo lookup and sync | PASS: router CI run 38862159980; CA integration run 38861558053 |
| S1 authentication | nls/v2_runtime.py certificate/RDR verification and signed lookup | wrong/expired certificate, revoked router, forged lookup | PASS — CI |
| S2 vIP + M1/M2 | nls/vip.py; nls/handshake.py; nls/v2_runtime.py | six-node lab emits `NLS_VIP_BEFORE`, `NLS_VIP_DURING`, `NLS_VIP_AFTER`; `test_m1_padding_covers_maximum_m2_amplification_budget` | PASS for Prompt 3 scope — run 38881019480: six-node lab `1 passed in 19.64s`; snapshots in artifact |
| S3 source cross-check/M3 | nls/v2_runtime.py:_handle_m2; nls/ca_client.py:lookup | `test_each_rdr_contract_field_mismatch_rejected_at_s3_and_s4` stage=S3; `test_revoked_router_rejected_s3_s4` stage=S3; `test_fresh_lookup_timestamps_are_bounded`; `test_newer_record_seq_is_freshness_not_identity_mismatch` | PASS for Prompt 3 scope — stage-specific mismatch/freshness tests passed |
| S4 destination cross-check/M4 | nls/v2_runtime.py:_handle_m3; nls/ca_client.py:lookup | `test_each_rdr_contract_field_mismatch_rejected_at_s3_and_s4` stage=S4; `test_revoked_router_rejected_s3_s4` stage=S4; `test_forged_ca_lookup_envelope_is_rejected` | PASS for Prompt 3 scope — stage-specific mismatch and forged-lookup tests passed |
| S5 endpoint switch | nls/v2_runtime.py:_handle_m4; nls/vip.py:release | six-node `NLS_VIP_*` snapshots; `test_retired_vip_data_packet_is_dropped_with_reason_code` | PASS for Prompt 3 scope — `NLS_VIP_AFTER` confirms removal; retired-vIP drop test passed |

V1–V11 source evidence is retained in `Documentation/security/threat-model.md` as the historical baseline. Prompt 4a introduces NLE2 as the only active data path. Prompt 4a is not considered secure or production-ready until the full gate, route isolation, netns TCP/UDP tests, and independent review are complete.

## Prompt 2 implementation evidence — router/client gate passed

- Client validates the pinned control identity, canonical-CBOR signatures, signed lookup nonce, lookup validity, directory expiry and monotonic sequence before atomically persisting `/var/lib/nlsxnetos/security/router-directory.json`: `nls/ca_client.py`.
- Revocation and freshness accessors are exposed as `is_revoked(serial, settings)` and `directory_freshness(settings)`; daemon consumption is reserved for prompts 3–4 as specified.
- Offline import is available as `sudo nlsxnetos router-ca import FILE`; the legacy unsigned YAML store no longer supplies trust entries.
- Real CI output from [router run 38862159980](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38861477771): Ubuntu 22.04 client/unit-security suite `66 passed in 5.52s`; Ubuntu 24.04 `66 passed in 4.20s`; four-node integration `1 passed in 15.52s`; ten-router IPv6 integration `1 passed in 8.02s`; lab scaffold `3 passed, 21 xfailed in 2.07s`; control-protocol compatibility `3 passed, 2 warnings in 0.05s`. Fresh-install jobs and dependency audit also passed on both OS versions. The 23 xfails are the deliberately gated Prompt 1 security cases assigned to later prompts, not passing implementation tests. CA unit/security and cross-repo results are in CA traceability.


## Historical Prompt 3 implementation run — not current gate evidence (GitHub Actions run 38874400473)

- Router repo branch: `feat/nls-v1`
- Tested implementation commit: `471694a7946fa6c7ed98fa9f90aead09c9b43e98` (older than the current branch head; not gate evidence for later changes)
- Run: https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38874400473
- Ubuntu 22.04 unit/security/package suite: **95 passed in 33.09s**
- Ubuntu 24.04 unit/security/package suite: **95 passed, 2 warnings in 16.40s**
- Four-node IPv6 vIP/handshake/forwarding/return-path lab: **1 passed in 17.81s**
- Ten-router IPv6 chain and termination lab: **1 passed in 9.66s**
- Spec scaffold: **3 passed, 7 xfailed in 0.96s**; the remaining strict xfails are later Prompt 4/5 data-plane cases, not Prompt 3 gate tests.
- Fresh-install jobs, dependency audit, and source-integrity checks: **PASS**.
- The vIP manager verifies the address in kernel `ip -6 addr show` output before continuing; the four-node lab checks that the address is recorded as verified and absent from the WAN interfaces after endpoint switch.


## Explicit S3/S4 comparison contract

At both S3 and S4, compare the embedded RDR with the freshly verified signed RDR using the stable identity/authorization fields only:

- `router_id`
- `ed25519_public_key`
- `rsa_encryption_public_key`
- `wan_endpoints`
- `gateway_ips`
- `prefixes`
- `certificate_serial`

The code constant is `RDR_S3_S4_COMPARE_FIELDS` in `nls/v2_runtime.py`. `status` is checked independently: the fresh RDR must be ACTIVE. `record_seq` is a monotonic freshness/rollback check in `nls/ca_client.py`, not an equality field; a higher sequence in a fresh lookup must not reject an otherwise identical peer. `issued_at` and `valid_until` are also per-lookup freshness metadata, not equality fields; both are validated for type, freshness, expiry, and a maximum 30-second validity interval. The signed policy is separate from the RDR and is checked through `allowed_suites`, `minimum_nls_version`, bundle expiry, and suite downgrade/proposal checks. The mismatch matrix tests each of the seven stable RDR fields at both S3 and S4; sequence-advance and timestamp-bound tests cover freshness separately. Status is tested through the independent ACTIVE-state check.

## Operator routes and source integrity

- The CLI command is implemented in `tools/router_cli/commands.py`: `nls route <prefix> via <router-id>`; `show running-config` renders persisted `router.nls_routes`.
- Route creation requires a fresh signed Router-CA directory, an active non-revoked known router ID, a route prefix covered by that router's CA-authorized prefixes, and no overlap with local interface prefixes or existing operator NLS routes. Invalid inputs fail before mutating the in-memory config. Existing kernel routes are not overwritten by `install_tun_routes`.
- Named regression tests: `tests/unit/test_router_cli_routes.py` (valid route, invalid-prefix/default/AF/unknown-router/overlap non-mutation and `show running-config`); `test_signed_rdr_bundle_import_never_installs_linux_routes`; `test_directory_sync_never_installs_linux_routes`; `test_routes_not_created_from_ca_peer_prefixes`. These tests must pass in exact-head CI before route isolation is promoted to PASS.
- Source integrity first verifies the original package checksum from inside `dist/`, then checks a tampered copy under the same basename in `/tmp`. That negative check is expected to emit a checksum mismatch; the workflow now prints `EXPECTED_NEGATIVE_CHECK` so the intentional rejection is distinguishable from a failed integrity check. The exact-head run must confirm the original checksum passes and the tampered copy is rejected.
- The six-node lab has client, Router A, intermediate WAN, Router B, server, and a Router-CA namespace. It exercises daemon-driven NLH2 M1–M4 and prints live WAN address snapshots before, during, and after bootstrap. CI runs this test with pytest `-s` and uploads the captured log as an artifact so `NLS_VIP_BEFORE`, `NLS_VIP_DURING`, and `NLS_VIP_AFTER` are visible and retained. The Router-CA lookup uses a signed test shim, not a live Router-CA service integration. NAT traversal is NOT VERIFIED.
- NAT traversal is **NOT VERIFIED**. The namespace lab does not exercise NAT.
- Prompt 3 exact-head evidence remains historical: run 38881754091 passed all nine jobs on SHA `3c7d4fbd6331c3b65bfd4d79282b0bd72c333989`. Prompt 4a commits have their own CI runs; failures are being corrected and no Prompt 4a gate-pass claim is made yet. NAT traversal remains NOT VERIFIED.


## Prompt 4a / 4b remaining strict-xfail items

Prompt 4a converts the tampered-ciphertext, replayed-packet, out-of-window, replay-window-poisoning, public-information forgery, and wrong-session/direction cases into active tests. The exact-head strict-xfail job must confirm these no longer xfail. Rekey remains assigned to Prompt 4b. The pcap confidentiality case remains xfail with an explicit reason until the WAN-node capture is available; if that capture can be added during Prompt 4, convert it there, otherwise complete it in Prompt 5. Every strict-xfail result must be reported with `pytest -q -rx`.
