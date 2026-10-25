# Stage 7 Design Proposal: Hybrid vIP Bootstrap Reachability

**Status:** Proposal only — not normative; no runtime implementation authorized by this document.  
**Scope:** Resolve the Stage 6 multi-hop reachability blocker without changing the frozen vIP derivation primitive.  
**Baseline:** Stage 6 branch `feat/stage6-hybrid-vip-handshake`, head `211c4e498cd4043e617111656a3d155aea324010`.  
**Related:** `docs/nls/MASTER_SPEC.md`, `docs/nls/DEVIATIONS.md`, `docs/nls/VIP_DERIVATION_TEST_VECTORS.md`.

## 1. Problem statement

Stage 6 derives a vIP from authenticated router identity material and a fresh handshake nonce. A derived IPv6 /128 is an identifier/address candidate; the derivation does not install a route, make the address topologically aggregatable, or teach transit routers where to forward it.

The current lab-only helper can add a temporary route on the destination router. That is insufficient in a multi-hop topology: intermediate routers still have no route for the arbitrary derived /128, so replies cannot reliably reach the initiator. A destination-local route is not a multi-hop bootstrap solution.

**Invariant:** Do not modify the vIP digest, truncate/alter its output to force routability, or weaken policy-v1 exclusions as a workaround.

## 2. Requirements

Any accepted solution MUST:

1. Preserve the frozen vIP derivation input encoding and digest output exactly.
2. Work across at least the four-node, six-node, and ten-router IPv6 labs, including reverse-path traffic.
3. Bind any installed route to authenticated router identities, the specific vIP, the active session/handshake, and a bounded lease.
4. Reject route claims for unverified peers, duplicate/conflicting vIPs, prohibited prefixes, expired sessions, revoked identities, and unauthorized destinations.
5. Remove routes on session close, timeout, revocation, failed rekey, daemon restart/reconciliation, and explicit teardown; cleanup failure must be observable and fail closed for new sessions.
6. Prevent unauthenticated route injection, route poisoning, reflection/amplification, and cross-session route reuse.
7. Avoid accepting a route merely because a record exists in the Router-CA registry; identity lookup is not route authorization.
8. Specify behavior for asymmetric routing, ECMP, stale routes, crash recovery, overlapping routes, and partial installation failure.
9. Define MTU/PMTU behavior and ensure the bootstrap control traffic itself has a reachable, non-recursive path.
10. Preserve normal IPv6 routing behavior for non-NLS traffic and never silently install a default route.

## 3. Candidate designs

### A — Authenticated per-vIP host-route distribution (preferred for evaluation)

After NLH2 authentication reaches the point specified by the final handshake state machine, the destination router requests/authorizes installation of an exact /128 route for the derived vIP. A narrowly scoped route-control mechanism distributes that host route to transit routers, with a signed/authenticated route object containing at minimum:

- protocol/version and unique route-event ID;
- vIP /128;
- owning destination router ID and authenticated certificate/key identifier;
- session or lease identifier and monotonically increasing generation;
- issued-at, expiry, and bounded maximum lease;
- authorization/policy version and revocation epoch;
- action (add, renew, withdraw) and replay-protection nonce/sequence.

Receivers validate signer authorization, freshness, lease bounds, prefix policy, generation monotonicity, and conflict rules before changing forwarding state. Route installation must be transactional or explicitly roll back partial installs. A route is usable only while the associated identity/session lease remains valid.

**Open design choice:** use the existing routing protocol (e.g. carefully constrained OSPFv3 host-route origination) or a separate authenticated route-control channel. OSPF reachability alone must not be treated as cryptographic authorization unless the selected deployment profile explicitly provides and validates the required authentication. The final spec must choose one mechanism and define interoperability.

**Advantages:** preserves the current derived-vIP semantics and lets transit routers learn the actual /128.  
**Risks:** expands the trusted control plane; route withdrawal and convergence become security-critical; requires authorization, anti-replay, flooding limits, restart reconciliation, and routing-daemon integration.

### B — Stable routable outer locator with vIP carried inside NLS

Use the authenticated WAN endpoint as the routable outer IPv6 locator and carry the derived vIP only inside an authenticated/encrypted NLS header or inner packet. This avoids advertising arbitrary vIP /128s into the underlay.

**Advantages:** avoids dynamic per-vIP underlay routes and may simplify multi-hop transit.  
**Risks:** changes the current M1 outer-source-equals-vIP requirement and potentially the packet/address model. It therefore requires an explicit normative spec amendment, updated anti-spoofing rules, and wire-compatibility review. Do not implement as a silent code-only deviation.

### C — Controller-managed route leases

A trusted route controller distributes per-vIP /128 leases to authorized routers and coordinates expiry/withdrawal.

**Advantages:** centralized policy and audit.  
**Risks:** controller availability becomes a bootstrap dependency; controller compromise has a large blast radius; enrollment, controller authentication, failover, and disconnected operation need a complete specification.

### D — Static routes or destination-only routes

Not acceptable as the production solution. Static configuration is useful only as a controlled diagnostic baseline. Destination-only routes do not solve transit forwarding and cannot satisfy the multi-hop acceptance gate.

## 4. Selected direction after routing/security analysis

**Select Design B for the v1 multi-hop/WAN profile:** use each router's authenticated, routable WAN locator for the outer IPv6 header during NLH2. Keep the derived `vip` as a cryptographically verified handshake-scoped identifier inside sealed M1; do not use it as an outer address, assign it to an interface, or install it in the kernel FIB.

This supersedes the earlier preliminary recommendation to prototype Design A. The deciding concern is that an arbitrary derived global `/128` is not inherently routable. Pre-handshake route distribution would require authorization before the handshake completes and could create a host-route hijack surface; it also cannot control non-participating Internet transit networks. A destination-only route demonstrably fails on multi-hop paths.

This selection preserves the vIP digest and derivation vectors but **does change the outer-addressing semantics**, so it must be incorporated into the normative master specification before code changes. It also means the handshake outer header reveals the routers' WAN locators; source-address-confidentiality claims must be limited to the separately specified post-M4 SourceToken data plane. If the product requirement insists that the derived vIP itself be the outer source, Design B is not equivalent; that requirement needs a separately approved delegated-prefix or relay design and remains blocked.

## 5. State and ordering requirements

The eventual normative state machine should distinguish at least:

- `DERIVED`: candidate computed and policy-checked; not routable yet.
- `AUTHENTICATED`: handshake peer identity and session authenticated.
- `ROUTE_PENDING`: route lease requested; no data-plane use permitted.
- `ROUTE_ACTIVE`: required transit route acknowledgements/convergence condition satisfied; data-plane use permitted.
- `WITHDRAWING`: route withdrawal issued; new packets denied while cleanup proceeds.
- `EXPIRED/REVOKED/FAILED`: data-plane use denied; reconciliation/cleanup required.

The final protocol must define exactly when M2/M3/M4 may be sent relative to route readiness. It must not claim route readiness based only on a local kernel route lookup. For distributed route propagation, specify the acknowledgment or bounded-convergence rule and how it prevents a half-open session from sending application data.

## 6. Threats and mandatory tests

| Test ID | Scenario | Required oracle |
|---|---|---|
| BR-01 | Four-node valid handshake | Both directions pass; route lifecycle is visible and bounded. |
| BR-02 | Six-node chain | Transit nodes learn and forward the exact /128; bidirectional traffic passes. |
| BR-03 | Ten-router IPv6 chain | No timeout due to missing derived-vIP route; all required routers have correct next hops. |
| BR-04 | Forged route object | Rejected; forwarding table unchanged. |
| BR-05 | Replay old add/renew/withdraw | Rejected by event ID, sequence/generation, expiry, or replay cache. |
| BR-06 | Route for unverified/revoked identity | Rejected or promptly withdrawn according to the specified revocation bound. |
| BR-07 | Same vIP claimed by two destinations | Deterministic conflict handling; never silently overwrite an active route. |
| BR-08 | Expired lease / crashed peer | Route removed within the normative bound; stale state reconciled after restart. |
| BR-09 | Partial propagation / one transit node unavailable | Session remains non-active or rolls back safely; no data-plane leak. |
| BR-10 | Unauthorized prefix, /0, or wider prefix | Rejected; only the authorized exact /128 is accepted. |
| BR-11 | Route withdrawal during active flow | No delivery to a different peer; session becomes unusable and cleanup is audited. |
| BR-12 | Route-control flood | Global/per-peer/per-interface limits prevent CPU, memory, and routing-table exhaustion. |
| BR-13 | Asymmetric path and ECMP | Defined behavior; return path is valid or session establishment fails closed. |
| BR-14 | PMTU and large payload | No fragmentation assumptions; bounded, tested behavior for handshake and data packets. |
| BR-15 | Router-CA outage/revocation | No new route activation from stale/unverified identity data; established-session behavior obeys the revocation SLA. |
| BR-16 | Ordinary IPv6 traffic | No unintended route hijack or change to unrelated prefixes. |

Every test must run on the actual final branch head and report command, environment, logs/artifacts, and pass/fail. Unit tests alone do not satisfy the multi-hop gate.

## 7. Spec decisions required before implementation

1. Choose A or B (C is an alternative if centralized control is an explicit deployment requirement).
2. For A, choose OSPFv3 origination versus a separate authenticated route-control channel.
3. Define route authorization authority and signer key lifecycle.
4. Define exact handshake message ordering and route-ready acknowledgment/convergence semantics.
5. Define maximum route lease, renewal cadence, revocation bound, withdrawal behavior, and restart reconciliation.
6. Define route conflict and multi-homing/ECMP policy.
7. Define which transit routers participate and how they authenticate/enroll.
8. Amend `MASTER_SPEC.md` with the selected normative design, message schema, state machine, threat model, and acceptance tests before runtime changes.

## 8. Exit criteria

This proposal is complete only when a selected design is approved and written into the normative master spec. Stage 6 remains blocked for multi-hop release until the selected mechanism is implemented, security-negative tests pass, and the four-node/six-node/ten-router labs pass on the same final commit. Keep this document marked as a proposal until that happens.
