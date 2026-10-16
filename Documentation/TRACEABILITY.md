# NLS v1 traceability — Prompt 3 gate NOT ACCEPTED (branch-head verification pending)

Prompt 1 established the source-evidence baseline and Prompt 2 implemented signed-directory trust. Prompt 3 implementation work is in progress on `feat/nls-v1`. The earlier green run on `471694a7946fa6c7ed98fa9f90aead09c9b43e98` is historical evidence only; it does not verify the current branch head or subsequent route, timestamp, six-node lab, and source-integrity changes. The Prompt 3 gate remains NOT ACCEPTED until exact-head CI and required lab output are reviewed.

| Requirement | Planned implementation file/function | Planned test | Status |
|---|---|---|---|
| R1 certificate chain/router ID/pinned root/active RDR | nls/ca_client.py:_verify_directory_envelope/lookup/directory_sync; nls/v2_runtime.py:_certificate | tests/security/test_ca_directory.py; NLH2 acceptance tests; cross-repo lookup | PASS — signed directory and active handshake admission |
| R2 random /128 assigned for 10 s | nls/vip.py:VIPManager; nls/v2_runtime.py:start/cleanup | `test_vip_expiry_removes_address_and_clears_ownership`; six-node NLH2 lab snapshots | PENDING — current-head `ip -6 addr` snapshots must pass |
| R3 encrypted signed M1 | nls/handshake.py:encode_v2_message/open_v2_message; nls/seal.py; nls/v2_runtime.py | `test_wrong_key_m1_is_screened_before_allocating_pending_state`; `test_m1_padding_covers_maximum_m2_amplification_budget`; protocol fuzz tests | IMPLEMENTED; exact-head CI pending |
| R4 encrypted M2 with RDR/gateway/suite/DH | nls/handshake.py strict M2 schema; nls/v2_runtime.py:_handle_m1/_handle_m2 | `test_sa_downgrade_rejected`; strict schema tests | IMPLEMENTED; exact-head CI pending |
| R5 endpoint switch/vIP retirement | nls/v2_runtime.py:_handle_m4/close/expire; nls/vip.py:release | `test_retired_vip_data_packet_is_dropped_with_reason_code`; six-node before/during/after snapshots | PENDING — current-head lab output required |
| R6 S3 live lookup/M2 comparison | nls/v2_runtime.py:_handle_m2; nls/ca_client.py:lookup | `test_each_rdr_contract_field_mismatch_rejected_at_s3_and_s4` (S3); `test_revoked_router_rejected_s3_s4`; `test_handshake_fails_closed_when_ca_is_unreachable` | TESTS ADDED; exact-head CI pending |
| R7 S4 M3/RDR check/M4 | nls/v2_runtime.py:_handle_m3; nls/ca_client.py:lookup | `test_each_rdr_contract_field_mismatch_rejected_at_s3_and_s4` (S4); `test_revoked_router_rejected_s3_s4`; `test_forged_ca_lookup_envelope_is_rejected` | TESTS ADDED; exact-head CI pending |
| R8 transcript-bound X25519/HKDF | nls/key_schedule.py:derive_session_keys | vectors/all-zero DH | Prompt 4 — data-plane integration and full security gate remain |
| R9 original packet inside NLE2 | nls/encapsulation.py:seal_data/open_data | pcap plaintext absence | not started |
| R10 sender authentication/tamper | nls/encapsulation.py:open_data; daemon data path | forgery/tamper | not started |
| R11 inner-source authorization/forwarding | nls/daemon.py:_handle_data; nls/routing.py | end-to-end/unauthorized source | not started |
| R12 128-window after AEAD | nls/replay.py:ReplayWindow | replay/out-of-window/poisoning | not started |
| R13 wire-silent failures/reason codes/safe logs | nls/logging.py; daemon failures | `test_logs_redact_keys_tokens_and_plaintext_canaries`; wire-silent failure tests | PARTIAL — log-canary test exists; wire-silent behavior not fully verified |
| R14 enrollment/revocation/signed RDR lookup | nls/ca_client.py:enroll/lookup/directory_sync/is_revoked/directory_freshness; security/trust/router_ca/store.py:import_bundle | tests/security/test_ca_directory.py; cross-repo lookup and sync | PASS: router CI run 38862159980; CA integration run 38861558053 |
| S1 authentication | nls/v2_runtime.py certificate/RDR verification and signed lookup | wrong/expired certificate, revoked router, forged lookup | PASS — CI |
| S2 vIP + M1/M2 | nls/vip.py; nls/handshake.py; nls/v2_runtime.py | six-node lab emits `NLS_VIP_BEFORE`, `NLS_VIP_DURING`, `NLS_VIP_AFTER`; `test_m1_padding_covers_maximum_m2_amplification_budget` | PENDING — current-head CI must prove snapshots |
| S3 source cross-check/M3 | nls/v2_runtime.py:_handle_m2; nls/ca_client.py:lookup | `test_each_rdr_contract_field_mismatch_rejected_at_s3_and_s4` stage=S3; `test_revoked_router_rejected_s3_s4` stage=S3; `test_fresh_lookup_timestamps_are_bounded` | TESTS ADDED; exact-head CI pending |
| S4 destination cross-check/M4 | nls/v2_runtime.py:_handle_m3; nls/ca_client.py:lookup | `test_each_rdr_contract_field_mismatch_rejected_at_s3_and_s4` stage=S4; `test_revoked_router_rejected_s3_s4` stage=S4; `test_forged_ca_lookup_envelope_is_rejected` | TESTS ADDED; exact-head CI pending |
| S5 endpoint switch | nls/v2_runtime.py:_handle_m4; nls/vip.py:release | six-node `NLS_VIP_*` snapshots; `test_retired_vip_data_packet_is_dropped_with_reason_code` | PENDING — current-head lab output required |

V1–V11 source evidence is retained in `Documentation/security/threat-model.md` as the historical baseline. The prior green run 38874400473 belongs to implementation commit `471694a7946fa6c7ed98fa9f90aead09c9b43e98`; it does not prove the current head. R8–R13 data-plane hardening remains future work, and the current NLE1 data plane is known forgeable under V3/V8.

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

At both S3 and S4, the embedded RDR identity/authorization record is compared against a freshly verified signed RDR using exactly these fields:

- `router_id`
- `ed25519_public_key`
- `rsa_encryption_public_key`
- `wan_endpoints`
- `gateway_ips`
- `prefixes`
- `certificate_serial`
- `status`
- `record_seq`

The code constant is `RDR_S3_S4_COMPARE_FIELDS` in `nls/v2_runtime.py`. `issued_at` and `valid_until` are per-lookup freshness metadata, not equality fields because each fresh lookup has different timestamps; both are validated for type, freshness, expiry, and a maximum 30-second validity interval. The signed policy is separate from the RDR and is checked through `allowed_suites`, `minimum_nls_version`, bundle expiry, and suite downgrade/proposal checks. The mismatch matrix covers each of the nine RDR fields at both S3 and S4; timestamp tests cover stale, future, expired, and overlong cases.

## Operator routes and source integrity

- The CLI command is implemented in `tools/router_cli/commands.py`: `nls route <prefix> via <router-id>`; `show running-config` renders persisted `router.nls_routes`.
- Route creation requires a fresh signed Router-CA directory, an active non-revoked known router ID, a route prefix covered by that router's CA-authorized prefixes, and no overlap with local interface prefixes or existing operator NLS routes. Invalid inputs fail before mutating the in-memory config. Existing kernel routes are not overwritten by `install_tun_routes`.
- Named regression tests added: `tests/unit/test_router_cli_routes.py`; `test_signed_rdr_bundle_import_never_installs_linux_routes`; `test_directory_sync_never_installs_linux_routes`; `test_routes_not_created_from_ca_peer_prefixes`. These are additions, not current-head CI evidence until the new workflow completes.
- The source-integrity manifest now records a basename from inside `dist/`, then checks a tampered copy under the same basename in `/tmp`. The earlier error was a relative-path mismatch (the manifest referred to a `dist/...` path while checking from `/tmp`), so the old negative check could fail because the file was missing rather than because tampering was detected. The corrected workflow is not yet verified on the current head.
- The six-node lab has client, Router A, intermediate WAN, Router B, server, and a Router-CA namespace. It exercises daemon-driven NLH2 M1–M4 and prints live WAN address snapshots before, during, and after bootstrap. The Router-CA lookup uses a signed test shim, not a live Router-CA service integration. Traffic remains the legacy NLE1 per-packet RSA data path and is explicitly labelled legacy-path interoperability; known V3/V8 forgery findings remain.
- NAT traversal is **NOT VERIFIED**. The namespace lab does not exercise NAT.
- Prompt 3 gate remains **NOT ACCEPTED** until exact current branch-head CI is green on Ubuntu 22.04 and 24.04, the six-node output demonstrates vIP presence only during bootstrap, and the strict-xfail output is reviewed. No Prompt 4 work is authorized by this traceability state.


## Strict-xfail matrix still assigned to later prompts

The historical strict-xfail run reported `3 passed, 7 xfailed in 0.96s`. The seven remaining strict xfails in `tests/integration/test_nls_v1_spec.py` are:

1. `test_tampered_ciphertext_rejected` — NLE2 data AEAD.
2. `test_replayed_packet_rejected` — NLE2 replay protection.
3. `test_out_of_window_packet_rejected` — NLE2 replay-window enforcement.
4. `test_replay_window_poisoning_rejected` — data-plane anti-poisoning.
5. `test_data_forgery_from_destination_public_key_rejected` — sender-authentication/data-plane forgery.
6. `test_rekey_at_packet_or_time_threshold` — rekey thresholds.
7. `test_pcap_contains_no_inner_packet_or_source_plaintext` — packet-capture confidentiality proof.

The updated workflow now uses `pytest -q -rx` for this matrix. That exact-head output is still pending; the historical count is not a claim about the current branch head.
