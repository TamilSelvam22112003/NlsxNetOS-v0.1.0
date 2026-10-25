# Deviations and conformance gaps

This file records observed departures from the shared master specification. Entries below are **not approved protocol deviations**; they are implementation gaps that must be resolved or explicitly accepted through a versioned specification decision.

## 2026-10-25 review

| ID | Specification requirement | Observed implementation | Reason/status | Required disposition |
|---|---|---|---|---|
| D-001 | Hybrid vIP amendment derives a candidate from the prescribed SHA-512 input and includes signed `vip_nonce`, `time_bucket`, and policy version in M1. | `nls/vip.py:VIPManager.allocate` selects a random address from a local pool; `nls/v2_runtime.py:HandshakeV2.start` does not include the amended derivation fields. | Implementation has not yet been migrated to the amended wire contract. Not an approved deviation. | Implement exactly as specified with deterministic vectors, address-policy tests, replay/freshness tests, and lab return-path validation. |
| D-002 | Post-M4 data records use NLD2 framing and explicit `source-only` or `source-destination` metadata mode, with no legacy fallback. | `nls/source_token.py` on `feat/nls-v1` still emits the counter-first SourceToken payload. | Metadata-mode implementation exists on a separate branch but is not in the reviewed target branch. Not an approved deviation. | Port the NLD2 implementation to `feat/nls-v1`, update both peers together, and reject legacy records. |
| D-003 | RDR schema validation rejects unknown fields. | `nls/ca_client.py:_validate_rdr_v2` checks required fields but does not explicitly reject every unknown payload field. | Strict-schema enforcement is incomplete. | Add exact-field-set validation and tests for extra fields, missing fields, legacy RDRs and invalid `original_ip_usable`. |
| D-004 | Session activation and endpoint switching must not leave endpoints with conflicting trust/session state. | Responder activates after sending M4, with no acknowledgement that the initiator received it. | UDP loss can produce a half-open state; recovery semantics are not fully demonstrated. | Add bounded M4 retransmission/recovery or an explicitly specified confirmation mechanism; test packet loss and duplicate M4. |
| D-005 | IPv6 packet sizing and MTU behavior must be interoperable and documented. | M1 padding is large enough to create fragmentation/PMTU risk on ordinary 1280-byte IPv6 paths. | The master specification records this as an open lab-validation risk. | Test fragmentation, loss and PMTU behavior without relaxing established acceptance thresholds; document safe deployment MTU. |
| D-006 | The Router-CA listener must have bounded resource use under unauthenticated connection floods. | Core lookup-specific rate/concurrency limits exist, but the listener starts a thread per accepted connection and has no visible global connection cap. | Connection-level protection remains to be verified/implemented. | Add a bounded admission strategy and safe load tests in the Core repository. |

## Status policy

A row remains open until the implementation, specification, tests, and cross-repository behavior agree. A green CI run that does not exercise the exact amended wire contract does not close the row.


| D-007 | M1 public-key fields must use one deterministic wire encoding and match the authoritative RDR. | Stage 6 encodes `source_ed25519_pub` and `source_rsa_pub` as DER SubjectPublicKeyInfo and rejects byte-level mismatch against the fresh signed RDR. | The minimal-M1 amendment names these fields but does not explicitly prescribe raw, PEM, or DER-SPKI encoding. | Tracked as OQ-2026-10-25-006. Confirm the wire encoding in MASTER_SPEC.md before merge; no fallback encoding is accepted. |
| D-008 | vIP derivation must be followed by exact policy validation without digest rewriting. | Stage 6 derives up to 256 candidates using fresh 32-byte nonces, validates policy-v1, and assigns only the accepted candidate as a short-lived interface address. | Interface assignment does not prove WAN reachability or upstream anti-spoofing acceptance. | Tracked as OQ-2026-10-25-007. Keep the PR draft until return-path, filtering, cleanup and PMTU tests pass in the target lab. |
