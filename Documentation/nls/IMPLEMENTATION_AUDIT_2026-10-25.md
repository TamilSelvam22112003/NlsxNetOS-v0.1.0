# NLS implementation audit — 2026-10-25

## Scope and evidence

This is a repository-first review of the approved `feat/nls-v1` branch. It is not a security certification. The review used the public GitHub files and workflow records; no local checkout or local test execution was available.

- NetOS reviewed base head: `a4dbb8ba75e6893c90e825fa420ec70876efba53`.
- NexOS Core reviewed base head: `1bb3b02bbcbbaa8bc1115584ec923fc7b9daa136`.
- Shared `docs/nls/MASTER_SPEC.md` blob on both feature branches: `8346c63f1926c73b7945265f5b92539376b4e9c1`.
- NetOS CI run `40091947203`: completed successfully, including ten-router IPv6, six-node NLH2 lab, throughput gates, package/install jobs and the specification scaffold.
- Core CI run `40091955351`: completed successfully, including unit/security suites and cross-repository control integration on Ubuntu 22.04 and 24.04.
- The successful runs are evidence for those exact tested revisions, not proof of complete master-spec conformance.
- A strict-xfail regression test for the NLD2 framing discrepancy was added after the reviewed NetOS base head in commit `02b41c328d50a4f5fe8e756ac5ab1b85ed0519f4`. Its result is **not yet verified**.

## High-priority implementation/specification discrepancies

| ID | Finding | Evidence | Status |
|---|---|---|---|
| P1 | The active handshake allocates a random /128 through `VIPManager`. The hybrid master-spec amendment requires the vIP to be derived from the specified ordered inputs using SHA-512, with signed `vip_nonce`, `time_bucket`, and policy version validation. The current M1 construction does not include those required derivation fields. | `nls/vip.py:VIPManager.allocate`; `nls/v2_runtime.py:HandshakeV2.start` (M1 construction); `docs/nls/MASTER_SPEC.md` sections “vIP derivation” and “Minimal M1 disclosure” | Confirmed mismatch |
| P2 | The reviewed `feat/nls-v1` data plane still emits the legacy counter-first SourceToken payload. The current master spec requires explicit NLD2 framing, a defined metadata mode, and no automatic fallback to the old payload. | `nls/source_token.py:seal_source_token_payload/open_source_token_payload`; `nls/daemon.py:NLSDaemon._handle_data`; master spec sections B.3–B.5 | Confirmed mismatch |
| P3 | The Router-CA client RDR validator checks mandatory v2 fields and their values but does not reject all unknown payload fields. The approved schema contract requires strict unknown-field rejection. | `nls/ca_client.py:_validate_rdr_v2` | Confirmed schema gap |
| P4 | The responder activates a session after sending M4, without receiving an acknowledgement that the initiator accepted M4. Loss of M4 can leave the responder active while the initiator remains pending until timeout. | `nls/v2_runtime.py:HandshakeV2._handle_m3/_handle_m4` | Confirmed lifecycle risk; loss/recovery test still required |
| P5 | Large padded M1/M2 handshake datagrams may require IPv6 fragmentation and may fail across networks that filter fragments or have restrictive MTUs. The specification itself records this as an open lab-validation risk. | `nls/v2_runtime.py:M2_MAX_DATAGRAM` and M1 padding; master spec “Remaining open questions” | Documented deployment risk; broader-path validation not verified |
| P6 | The Core TCP listener creates a thread for each accepted connection. Lookup-specific rate/concurrency limits exist, but a separate global bound on unauthenticated open connections is not evident in the reviewed listener. | Core `src/nls_nexos_core/control.py:NLSControlServer.serve_forever`; lookup caps in `_dispatch` | DoS hardening gap; exploitability not tested |
| P7 | The NLS internal LSDB/registry and operator route logic do not prove actual OSPF/OSPFv3 LSA propagation or BGP/RIP integration. | `nls/lsdb.py`, `nls/routing.py`, `Documentation/nls/routing-integration-workflow.md`; master spec routing boundary | Not verified |

## Requested V1–V11 verification table

The V1–V11 items in the master prompt are treated as hypotheses to verify, not as presumed defects.

| ID | Hypothesis | Finding on `feat/nls-v1` | Status |
|---|---|---|---|
| V1 | CA revocation data is written but never read by the data plane. | Active handshake record validation calls `ca_client.is_revoked`; daemon lifecycle code also checks revocation. Exact-head active-session revocation acceptance remains a separate test gate. | Disputed as stated; active revocation lifecycle partially verified |
| V2 | Handshake identity is only a self-signed dictionary matched to local YAML; CA is not consulted. | Active `HandshakeV2` uses signed Router Directory Records and fresh CA lookups. Legacy handshake helpers remain in the module but are not proof of active-path behavior. | Disputed for active NLH2 path |
| V3 | Session keys are derived but not used for data packets. | Active daemon passes directional session keys to SourceToken payload sealing/opening. | Disputed |
| V4 | vIP is only a string and is not assigned or used as outer source. | `VIPManager` assigns a temporary IPv6 /128 and binds a socket to it. The derivation algorithm still disagrees with the current amended specification. | Disputed as stated; vIP derivation mismatch confirmed |
| V5 | Active handshake is cleartext signed JSON. | Active runtime uses NLH2 sealed messages and canonical CBOR. Legacy NLSH/JSON helpers remain and must stay out of active dispatch. | Disputed for active NLH2 path |
| V6 | Startup requires a CA endpoint to equal the local listen endpoint and requires a WAN role. | The active v2 path selects an interface from the route and uses signed directory endpoints; full NAT and deployment compatibility are not established. | Partially verified |
| V7 | A forged high sequence number can poison the replay window. | `ReplayWindow` requires authentication before `mark`; existing security test checks that tampered ciphertext does not advance the window. | Disputed; retain regression coverage |
| V8 | A packet forged using only the destination RSA public key and clear session fields is accepted by `open_ip_packet`. | The active `feat/nls-v1` data path uses directional session AEAD keys, not the legacy RSA-wrapped-key NLE2 path. Active-path source authentication is therefore different from the historical helper. | Disputed for active path; keep legacy code out of dispatch |
| V9 | Per-packet RSA-3072 OAEP unwrap bounds active throughput. | Active SourceToken data path uses symmetric session keys. CI includes historical legacy benchmark steps, but no benchmark values were independently extracted in this review. | Disputed for active path; quantitative performance not re-measured |
| V10 | Any failed INIT blocks a peer for 60 seconds, allowing garbage INIT lockout. | Active NLH2 runtime applies global/interface/source-prefix resource controls; existing security test covers garbage M1 not blocking a router identity. | Disputed for active path; retain regression coverage |
| V11 | Router-CA metadata creates Linux routes. | Operator route installation is separate from CA metadata; existing tests assert that directory sync does not install routes. | Disputed; retain regression coverage |

## Architecture and acceptance boundaries

- **Control plane:** NLS Control v1 uses TCP 4790 and is separate from NLH2.
- **Router handshake:** NLH2 M1–M4 uses signed/sealed messages, CA-signed RDRs, freshness checks, transcript validation and key confirmation.
- **Data plane:** SourceToken-based demultiplexing is active, but the reviewed feature branch's payload framing does not yet match the NLD2 amendment.
- **Trust state:** `VIPVerificationTable` stages candidate identity and requires both CA-record and peer-signature checks before verification; `TrustTable` only promotes a VERIFIED row.
- **Routing:** operator-owned routes remain distinct from trust metadata. Actual routing-daemon LSDB/LSA propagation is not established by the internal JSON LSDB alone.
- **Security assurance:** passing CI does not replace independent review of the custom control protocol, hostile-network testing, or full wire-format interoperability testing.

## Gate result

**Baseline review: PARTIALLY VERIFIED.** The selected feature branch has meaningful passing CI evidence, but the vIP derivation and NLD2 wire-format mismatches prevent a claim of full master-spec conformance. No product code was changed in this audit. The strict-xfail framing test was added for the next CI run; its result remains **not verified**.

## Next actions

1. Run CI on the audit/test commit and record the actual xfail count and all failures.
2. Implement the amended vIP derivation and M1 field contract only after verifying exact canonical field encodings and lab return-path behavior.
3. Port the NLD2 metadata-mode data plane to `feat/nls-v1` with no legacy fallback; validate both peers together.
4. Add tests for M4 loss/recovery, strict unknown-field rejection, connection-level DoS limits, MTU/fragmentation, and revocation during an active session.
5. Keep OSPF/OSPFv3 LSA propagation and BGP/RIP integration marked not verified until actual interoperability tests exist.
