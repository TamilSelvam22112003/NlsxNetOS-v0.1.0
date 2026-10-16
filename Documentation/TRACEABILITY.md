# NLS v1 traceability — Prompt 2 gate record

Prompt 1 established the source-evidence baseline. Prompt 2 implements the CA client and signed directory trust path; handshake and data-plane requirements assigned to prompts 3–4 remain unstarted.

| Requirement | Planned implementation file/function | Planned test | Status |
|---|---|---|---|
| R1 certificate chain/router ID/pinned root/active RDR | nls/ca_client.py:_verify_directory_envelope/lookup/directory_sync; security/trust/router_ca/store.py:verified_bundle | tests/security/test_ca_directory.py; cross-repo lookup | PASS for signed client/directory scope; live handshake S1 integration remains Prompt 3 |
| R2 random /128 assigned for 10 s | nls/vip.py:allocate/assign/release; daemon lifecycle | expiry/reuse, pcap source | not started |
| R3 encrypted signed M1 | nls/handshake.py:build_m1/parse_m1; nls/seal.py | handshake/confidentiality/amplification | not started |
| R4 encrypted M2 with RDR/gateway/suite/DH | nls/handshake.py:build_m2/parse_m2 | schema/tamper | not started |
| R5 endpoint switch/vIP retirement | nls/daemon.py:complete_endpoint_switch; nls/vip.py | no vIP after switch/cleanup | not started |
| R6 S3 live lookup/M2 comparison | nls/handshake.py:verify_m2_against_rdr; ca_client.py:lookup | signed lookup client implemented; M2 handshake comparison remains Prompt 3 | partial |
| R7 S4 M3/RDR check/M4 | nls/handshake.py:verify_m3_and_build_m4; ca_client.py:lookup | signed lookup client implemented; M3/M4 integration remains Prompt 3 | partial |
| R8 transcript-bound X25519/HKDF | nls/key_schedule.py:derive_session_keys | vectors/all-zero DH | not started |
| R9 original packet inside NLE2 | nls/encapsulation.py:seal_data/open_data | pcap plaintext absence | not started |
| R10 sender authentication/tamper | nls/encapsulation.py:open_data; daemon data path | forgery/tamper | not started |
| R11 inner-source authorization/forwarding | nls/daemon.py:_handle_data; nls/routing.py | end-to-end/unauthorized source | not started |
| R12 128-window after AEAD | nls/replay.py:ReplayWindow | replay/out-of-window/poisoning | not started |
| R13 wire-silent failures/reason codes/safe logs | nls/logging.py; daemon failures | canary/silent failure | not started |
| R14 enrollment/revocation/signed RDR lookup | nls/ca_client.py:enroll/lookup/directory_sync/is_revoked/directory_freshness; security/trust/router_ca/store.py:import_bundle | tests/security/test_ca_directory.py; cross-repo lookup and sync | PASS: router CI run 38862159980; CA integration run 38861558053 |
| S1 authentication | certificate/RDR verifier; nls/ca_client.py:lookup and verified directory | CA client verifies signed records, but legacy handshake still uses self-asserted identity data | partial; handshake replacement is Prompt 3 |
| S2 vIP + M1/M2 | nls/vip.py; nls/handshake.py | handshake/amplification/vIP capture | not started |
| S3 source cross-check/M3 | handshake + ca_client lookup | S3 mismatch | not started |
| S4 destination cross-check/M4 | handshake + ca_client lookup | S4 mismatch/forged CA | not started |
| S5 endpoint switch | daemon + vip | vIP removal/abort cleanup | not started |

V1–V11 source evidence is in Documentation/security/threat-model.md. No full handshake/data-plane requirement is marked complete in Prompt 2. R1/R14 client and directory scope passed; S1 handshake integration and S3/S4 checks remain open.

## Prompt 2 implementation evidence — router/client gate passed

- Client validates the pinned control identity, canonical-CBOR signatures, signed lookup nonce, lookup validity, directory expiry and monotonic sequence before atomically persisting `/var/lib/nlsxnetos/security/router-directory.json`: `nls/ca_client.py`.
- Revocation and freshness accessors are exposed as `is_revoked(serial, settings)` and `directory_freshness(settings)`; daemon consumption is reserved for prompts 3–4 as specified.
- Offline import is available as `sudo nlsxnetos router-ca import FILE`; the legacy unsigned YAML store no longer supplies trust entries.
- Real CI output from [router run 38862159980](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38861477771): Ubuntu 22.04 client/unit-security suite `66 passed in 5.52s`; Ubuntu 24.04 `66 passed in 4.20s`; four-node integration `1 passed in 15.52s`; ten-router IPv6 integration `1 passed in 8.02s`; lab scaffold `3 passed, 21 xfailed in 2.07s`; control-protocol compatibility `3 passed, 2 warnings in 0.05s`. Fresh-install jobs and dependency audit also passed on both OS versions. The 23 xfails are the deliberately gated Prompt 1 security cases assigned to later prompts, not passing implementation tests. CA unit/security and cross-repo results are in CA traceability.
