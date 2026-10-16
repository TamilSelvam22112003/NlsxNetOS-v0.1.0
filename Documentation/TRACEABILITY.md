# NLS v1 traceability — Prompt 3 gate passed (implementation commit 471694a7946f)

Prompt 1 established the source-evidence baseline and Prompt 2 implemented signed-directory trust. Prompt 3 implements the NLH2 handshake and vIP lifecycle. The Prompt 3 gate passed on implementation commit 471694a7946fa6c7ed98fa9f90aead09c9b43e98; the evidence below links the real Ubuntu 22.04/24.04 and namespace-lab run.

| Requirement | Planned implementation file/function | Planned test | Status |
|---|---|---|---|
| R1 certificate chain/router ID/pinned root/active RDR | nls/ca_client.py:_verify_directory_envelope/lookup/directory_sync; nls/v2_runtime.py:_certificate | tests/security/test_ca_directory.py; NLH2 acceptance tests; cross-repo lookup | PASS — signed directory and active handshake admission |
| R2 random /128 assigned for 10 s | nls/vip.py:VIPManager; nls/v2_runtime.py:start/cleanup | expiry/reuse; four-node netns vIP lifecycle | PASS — CI |
| R3 encrypted signed M1 | nls/handshake.py:encode_v2_message/open_v2_message; nls/seal.py; nls/v2_runtime.py | wrong-key M1, signature, amplification, fuzz | PASS — CI |
| R4 encrypted M2 with RDR/gateway/suite/DH | nls/handshake.py strict M2 schema; nls/v2_runtime.py:_handle_m1/_handle_m2 | strict schema, signed RDR, SA downgrade | PASS — CI/lab |
| R5 endpoint switch/vIP retirement | nls/v2_runtime.py:_handle_m4/close/expire; nls/vip.py:release | vIP only during bootstrap; VIP_AFTER_SWITCH | PASS — CI/lab |
| R6 S3 live lookup/M2 comparison | nls/v2_runtime.py:_handle_m2; nls/ca_client.py:lookup | S3 mismatch, revoked S3, CA unavailable | PASS — CI |
| R7 S4 M3/RDR check/M4 | nls/v2_runtime.py:_handle_m3; nls/ca_client.py:lookup | S4 mismatch, revoked S4, forged CA response | PASS — CI |
| R8 transcript-bound X25519/HKDF | nls/key_schedule.py:derive_session_keys | vectors/all-zero DH | Prompt 4 — data-plane integration and full security gate remain |
| R9 original packet inside NLE2 | nls/encapsulation.py:seal_data/open_data | pcap plaintext absence | not started |
| R10 sender authentication/tamper | nls/encapsulation.py:open_data; daemon data path | forgery/tamper | not started |
| R11 inner-source authorization/forwarding | nls/daemon.py:_handle_data; nls/routing.py | end-to-end/unauthorized source | not started |
| R12 128-window after AEAD | nls/replay.py:ReplayWindow | replay/out-of-window/poisoning | not started |
| R13 wire-silent failures/reason codes/safe logs | nls/logging.py; daemon failures | canary/silent failure | not started |
| R14 enrollment/revocation/signed RDR lookup | nls/ca_client.py:enroll/lookup/directory_sync/is_revoked/directory_freshness; security/trust/router_ca/store.py:import_bundle | tests/security/test_ca_directory.py; cross-repo lookup and sync | PASS: router CI run 38862159980; CA integration run 38861558053 |
| S1 authentication | nls/v2_runtime.py certificate/RDR verification and signed lookup | wrong/expired certificate, revoked router, forged lookup | PASS — CI |
| S2 vIP + M1/M2 | nls/vip.py; nls/handshake.py; nls/v2_runtime.py | vIP assigned and verified by `ip -6 addr`, amplification bound | PASS — CI/lab |
| S3 source cross-check/M3 | nls/v2_runtime.py:_handle_m2; nls/ca_client.py:lookup | S3 mismatch/revocation/CA unreachable | PASS — CI |
| S4 destination cross-check/M4 | nls/v2_runtime.py:_handle_m3; nls/ca_client.py:lookup | S4 mismatch/revocation/forged CA | PASS — CI |
| S5 endpoint switch | nls/v2_runtime.py:_handle_m4; nls/vip.py:release | bootstrap-only vIP and post-switch rejection | PASS — CI/lab |

V1–V11 source evidence is retained in Documentation/security/threat-model.md as the historical baseline. Prompt 3 passed its gate on implementation commit `471694a7946fa6c7ed98fa9f90aead09c9b43e98` (run 38874400473). R8–R13 data-plane hardening/integration remains assigned to Prompt 4; despite the handshake key schedule existing for NLH2, the v1 data plane is intentionally retained and is not secure against the V3/V8 forgery findings.

## Prompt 2 implementation evidence — router/client gate passed

- Client validates the pinned control identity, canonical-CBOR signatures, signed lookup nonce, lookup validity, directory expiry and monotonic sequence before atomically persisting `/var/lib/nlsxnetos/security/router-directory.json`: `nls/ca_client.py`.
- Revocation and freshness accessors are exposed as `is_revoked(serial, settings)` and `directory_freshness(settings)`; daemon consumption is reserved for prompts 3–4 as specified.
- Offline import is available as `sudo nlsxnetos router-ca import FILE`; the legacy unsigned YAML store no longer supplies trust entries.
- Real CI output from [router run 38862159980](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38861477771): Ubuntu 22.04 client/unit-security suite `66 passed in 5.52s`; Ubuntu 24.04 `66 passed in 4.20s`; four-node integration `1 passed in 15.52s`; ten-router IPv6 integration `1 passed in 8.02s`; lab scaffold `3 passed, 21 xfailed in 2.07s`; control-protocol compatibility `3 passed, 2 warnings in 0.05s`. Fresh-install jobs and dependency audit also passed on both OS versions. The 23 xfails are the deliberately gated Prompt 1 security cases assigned to later prompts, not passing implementation tests. CA unit/security and cross-repo results are in CA traceability.


## Prompt 3 gate evidence — GitHub Actions run 38874400473

- Router repo branch: `feat/nls-v1`
- Tested implementation commit: `471694a7946fa6c7ed98fa9f90aead09c9b43e98`
- Run: https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38874400473
- Ubuntu 22.04 unit/security/package suite: **95 passed in 33.09s**
- Ubuntu 24.04 unit/security/package suite: **95 passed, 2 warnings in 16.40s**
- Four-node IPv6 vIP/handshake/forwarding/return-path lab: **1 passed in 17.81s**
- Ten-router IPv6 chain and termination lab: **1 passed in 9.66s**
- Spec scaffold: **3 passed, 7 xfailed in 0.96s**; the remaining strict xfails are later Prompt 4/5 data-plane cases, not Prompt 3 gate tests.
- Fresh-install jobs, dependency audit, and source-integrity checks: **PASS**.
- The vIP manager verifies the address in kernel `ip -6 addr show` output before continuing; the four-node lab checks that the address is recorded as verified and absent from the WAN interfaces after endpoint switch.
