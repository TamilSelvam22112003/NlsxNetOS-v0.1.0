# Stage 7 Design Proposal: Hybrid vIP Bootstrap Reachability

**Status:** Design rationale for the Stage 7 normative amendment in `docs/nls/MASTER_SPEC.md`; implementation is under review in draft PR #54 and is not release-certified.  
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

### A — Authenticated per-vIP host-route distribution (not selected for v1)

This design is not selected for the v1 multi-hop/WAN profile. It would distribute a host route for an arbitrary derived global /128 before M2 can reliably return, requiring a bootstrap authorization path and creating a route-hijack risk. It also cannot control non-participating Internet transit. Do not implement it under this proposal.

**Disposition:** Rejected for this profile. It may be reconsidered only for a closed, operator-controlled address domain with a separate security design, explicit route authorization, and a non-global delegated prefix. It MUST NOT install arbitrary SHA-512-derived global /128s into the ordinary kernel FIB.

### B — Stable routable outer locator with vIP carried inside sealed M1 (SELECTED)

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

The implementation state machine must distinguish at least:

- `VIP_DERIVED`: candidate computed and policy-checked; retained as a sealed-handshake/session identifier only.
- `M1_SENT`: M1 sent from S's authenticated WAN locator to D's authenticated WAN locator.
- `PEER_AUTHENTICATED`: required fresh Router-CA lookups, key checks, and transcript checks have succeeded.
- `SESSION_ESTABLISHED`: M4/key confirmation succeeded; the session is eligible for the separately specified post-M4 data plane.
- `CLOSED/EXPIRED/REVOKED/FAILED`: forwarding denied and exact session state cleaned up.

No route-readiness acknowledgment is required for the derived vIP because it is not a routing address. Handshake state must not create or remove a vIP interface address, FIB route, or OSPF advertisement.

## 6. Threats and mandatory tests

| Test ID | Scenario | Required oracle |
|---|---|---|
| BR-01 | Four-node valid handshake | Both directions pass using authenticated WAN locators; no derived-vIP route exists. |
| BR-02 | Six-node chain | Transit routers forward via ordinary WAN routing; bidirectional traffic passes. |
| BR-03 | Ten-router IPv6 chain | No handshake timeout caused by a derived-vIP return route; no derived-vIP FIB entries exist. |
| BR-04 | Forged or mismatched outer locator | Rejected; trusted binding and forwarding table unchanged. |
| BR-05 | Replay old M1/M2/M3/M4 | Rejected by transcript binding, nonce/session replay protection, and state machine. |
| BR-06 | Endpoint record belongs to unverified/revoked identity | Rejected; session fails closed according to the revocation bound. |
| BR-07 | vIP collision or duplicate binding | Session-scoped binding conflict handled deterministically; no route installation. |
| BR-08 | Expired session / crashed peer | Session binding expires and restart cleanup reconciles state; no vIP route cleanup needed. |
| BR-09 | Transit route to real WAN locator unavailable | Handshake fails closed without a derived-vIP route workaround. |
| BR-10 | Attempt to install a derived-vIP /128 or broader route | Rejected; ordinary FIB remains unchanged. |
| BR-11 | Session teardown during active flow | Exact session binding is invalidated; unrelated routes and sessions remain unchanged. |
| BR-12 | Handshake flood | Global/per-interface/per-source-/64 controls bound CPU, memory, and CA lookups. |
| BR-13 | Asymmetric path and ECMP | Defined behavior; return path is valid or session establishment fails closed. |
| BR-14 | PMTU and large payload | No fragmentation assumptions; bounded, tested behavior for handshake and data packets. |
| BR-15 | Router-CA outage/revocation | No new session from stale/unverified identity data; established-session behavior obeys the revocation SLA. |
| BR-16 | Ordinary IPv6 traffic | No derived-vIP address, FIB route, or OSPF advertisement; unrelated routes unchanged. |

Every test must run on the actual final branch head and report command, environment, logs/artifacts, and pass/fail. Unit tests alone do not satisfy the multi-hop gate.

## 7. Normative decision and implementation status

The Stage 7 amendment at the end of `docs/nls/MASTER_SPEC.md` selects **Design B: routable outer WAN locators** for the v1 multi-hop/WAN profile. The derived vIP remains an unchanged, signed/sealed handshake identifier. It is not an outer source/destination, interface address, kernel route, or OSPF advertisement.

The decision changes earlier outer-addressing semantics and must be reviewed as a normative protocol change. It does not claim source-address confidentiality during M1-M4; that claim applies only to the separately specified post-M4 SourceToken data plane.

Implementation work on `feat/stage7-routable-outer-locator` removes derived-vIP address/route allocation, sends M1-M4 through the ordinary NLS UDP socket, and validates observed peer address and UDP port against the authoritative primary endpoint from the signed Router-CA record. Unit tests cover exact endpoint matching and mismatch rejection. The six-node and ten-router lab results are not yet known for this implementation branch.

Before release, reviewers must verify:
1. The selected Stage 7 amendment is accepted into the normative spec baseline.
2. M1-M4 source/destination locators are consistent with authenticated RDR primary endpoints and the deployment's NAT/source-validation policy.
3. Captures prove no derived vIP is assigned, routed, or emitted as an outer locator.
4. Four-node, six-node, and ten-router bidirectional tests pass on the same commit.
5. Security-negative tests, revocation/freshness tests, MTU/PMTU tests, and performance/evidence gates pass.

## 8. Exit criteria

The selected design is recorded in the Stage 7 amendment on the docs branches, but remains unmerged pending review. Stage 6 remains blocked for multi-hop release until the amendment is accepted, implementation conforms, security-negative tests pass, and the four-node/six-node/ten-router labs pass on the same final commit.
