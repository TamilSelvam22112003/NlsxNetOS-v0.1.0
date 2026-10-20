# Cross-repository architecture reconciliation

Date: 2026-10-20
Branch target: `feat/nls-v1`

## Protocol boundaries

The authoritative `docs/nls/MASTER_SPEC.md` contains a base NLH2 handshake specification and later amendments. Apply amendments only to the fields and behaviors they explicitly supersede; retain the remaining NLH2 authentication, transcript, key-schedule, freshness, replay, and failure requirements.

The current implementation must keep three protocol surfaces distinct:

1. **NLS Control v1 (`NLSC`, TCP 4790):** router enrollment, authenticated control records, registry lookup/synchronization, policy and revocation state.
2. **Router handshake (`NLH2`):** sealed, signed, versioned router-to-router handshake messages and authenticated session establishment.
3. **NLS data plane:** current master-spec SourceToken amendment supersedes the legacy NLE2 outer header/data-demultiplexing behavior where explicitly stated. The resulting encrypted payload carries the original IP packet and its message type; per-direction SourceTokens select the data session.

Do not treat an OSPF/BGP adjacency, a reachable endpoint, or an NLSC control connection as proof that an NLH2 data session is established.

## Required cross-repository contracts

| Contract | NetOS responsibility | NexOS Core responsibility |
|---|---|---|
| Router identity | Keep private keys local; validate CA-issued certificate and signed directory data | Issue/revoke certificates and maintain authoritative router registry |
| RDR | Validate exact schema, signature, status, freshness and field consistency | Emit canonical signed RDRs; preserve ordered endpoint semantics and enforce uniqueness |
| Peer lookup | Authenticate lookup, validate nonce-bound signed response, fail closed on stale/invalid response | Authorize active caller, rate-limit, sign response, audit lookup |
| Protocol formats | NLH2 handshake and data-plane behavior per spec | NLSC control channel; CA APIs and registry |
| Revocation/freshness | Enforce policy at session admission and during session lifecycle | Publish signed revocation/directory state and enforce sequence/freshness |
| Routing | Only operator-configured routes may enter the NLS tunnel; preserve FRR control packets | Registry metadata authorizes peers but MUST NOT create kernel routes |
| Shared control definitions | Keep `nls/control_protocol.py` synchronized with Core's copy and test compatibility | Same shared wire/API contract; compatibility test must import both copies |

## Confirmed implementation conflict

NetOS `nls/handshake.py` retains legacy `NLSH`/JSON helpers, while the active daemon imports the v2 NLH2 APIs from the same module. The active path still requires field-by-field validation against the latest amendments: the current M1 field names/disclosures and random vIP allocation do not yet match the hybrid/minimal-disclosure specification. Separately, `nls/encapsulation.py` still implements the legacy NLE2 data header; SourceToken data-plane migration remains outstanding. Do not conflate the legacy helper functions with the active handshake runtime.

Core `src/nls_nexos_core/control_protocol.py` declares `MAGIC=b"NLSC"` and canonical JSON. This is the separate control channel and must not be mechanically converted to NLH2 as if both were the same protocol.

## Gate before data-plane changes

Before modifying data-plane code, identify the exact current SourceToken implementation, session-table lifecycle, packet ingress/egress mechanism, and all consumers of legacy NLE2. Add regression tests for dispatch, authenticated replay-window commit, token collision, session teardown, and no route creation from CA metadata. Run the tests and preserve complete output. No test execution is claimed by this document.
