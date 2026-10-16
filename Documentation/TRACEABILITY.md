# NLS v1 traceability — Prompt 1 baseline

All target implementation statuses are not started. Prompt 1 verifies source, updates docs and scaffolds tests only.

| Requirement | Planned implementation file/function | Planned test | Status |
|---|---|---|---|
| R1 certificate chain/router ID/pinned root/active RDR | nls/ca_client.py:_verify_directory_envelope/lookup/directory_sync; security/trust/router_ca/store.py:verified_bundle | tests/security/test_ca_directory.py; cross-repo lookup | implementation added; CI gate pending |
| R2 random /128 assigned for 10 s | nls/vip.py:allocate/assign/release; daemon lifecycle | expiry/reuse, pcap source | not started |
| R3 encrypted signed M1 | nls/handshake.py:build_m1/parse_m1; nls/seal.py | handshake/confidentiality/amplification | not started |
| R4 encrypted M2 with RDR/gateway/suite/DH | nls/handshake.py:build_m2/parse_m2 | schema/tamper | not started |
| R5 endpoint switch/vIP retirement | nls/daemon.py:complete_endpoint_switch; nls/vip.py | no vIP after switch/cleanup | not started |
| R6 S3 live lookup/M2 comparison | nls/handshake.py:verify_m2_against_rdr; ca_client.py:lookup | S3 mismatch | not started |
| R7 S4 M3/RDR check/M4 | nls/handshake.py:verify_m3_and_build_m4 | S4 mismatch/order | not started |
| R8 transcript-bound X25519/HKDF | nls/key_schedule.py:derive_session_keys | vectors/all-zero DH | not started |
| R9 original packet inside NLE2 | nls/encapsulation.py:seal_data/open_data | pcap plaintext absence | not started |
| R10 sender authentication/tamper | nls/encapsulation.py:open_data; daemon data path | forgery/tamper | not started |
| R11 inner-source authorization/forwarding | nls/daemon.py:_handle_data; nls/routing.py | end-to-end/unauthorized source | not started |
| R12 128-window after AEAD | nls/replay.py:ReplayWindow | replay/out-of-window/poisoning | not started |
| R13 wire-silent failures/reason codes/safe logs | nls/logging.py; daemon failures | canary/silent failure | not started |
| R14 enrollment/revocation/signed RDR lookup | nls/ca_client.py:enroll/lookup/directory_sync/is_revoked/directory_freshness; security/trust/router_ca/store.py:import_bundle | tests/security/test_ca_directory.py; cross-repo lookup and sync | implementation added; CI gate pending |
| S1 authentication | certificate/RDR verifier | wrong/revoked/expired | not started |
| S2 vIP + M1/M2 | nls/vip.py; nls/handshake.py | handshake/amplification/vIP capture | not started |
| S3 source cross-check/M3 | handshake + ca_client lookup | S3 mismatch | not started |
| S4 destination cross-check/M4 | handshake + ca_client lookup | S4 mismatch/forged CA | not started |
| S5 endpoint switch | daemon + vip | vIP removal/abort cleanup | not started |

V1–V11 source evidence is in Documentation/security/threat-model.md. No target implementation is marked complete.

## Prompt 2 implementation evidence (gate pending)

- Client validates the pinned control identity, canonical-CBOR signatures, signed lookup nonce, lookup validity, directory expiry and monotonic sequence before atomically persisting `/var/lib/nlsxnetos/security/router-directory.json`: `nls/ca_client.py`.
- Revocation and freshness accessors are exposed as `is_revoked(serial, settings)` and `directory_freshness(settings)`; daemon consumption is reserved for prompts 3–4 as specified.
- Offline import is available as `sudo nlsxnetos router-ca import FILE`; the legacy unsigned YAML store no longer supplies trust entries.
- No requirement is marked gate-passed until Ubuntu 22.04 and 24.04 CI outputs are observed.
