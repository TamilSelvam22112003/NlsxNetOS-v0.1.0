# NLS implementation deviations

This file records intentional implementation differences from the frozen protocol specification. It does not override the normative specification; each item requires reviewer approval before release.

## DEV-001 — Lab return-route next hop

- **Status:** Proposed in draft Stage 6; not release-approved.
- **Specification:** The lab-only temporary route may route the derived vIP via the source router's authoritative `originalIP`.
- **Implementation:** The lab-only helper resolves the kernel-selected route to that authoritative `originalIP` and installs the derived-vIP /128 via the selected gateway when one exists; if the source is directly connected, it uses the source `originalIP` as next hop.
- **Reason:** Linux `via` routes require a valid next hop on the selected link. A source router several hops away is not necessarily a directly reachable next hop. Following the existing route to the authenticated `originalIP` supports multi-hop lab topology without rewriting the derived vIP.
- **Security boundary:** The route is installed only after M1 signature checks, fresh authenticated source and destination Router-CA lookups, vIP recomputation, policy validation, outer-source equality, and nonce replay checks. It requires explicit `nls.deployment_mode: lab` and `nls.vip.lab_temporary_route.enabled: true`. Both default to production/disabled. Production mode rejects an attempt to enable it.
- **Cleanup:** The route is tracked by handshake session and deleted after M4 send or on M1 failure, handshake abort, or timeout. A failed deletion is logged and the tracked route remains available for retry.
- **Observed CI result (2026-10-25):** The six-node and ten-router handshake/return-path jobs still timed out after the destination-only route was installed. Transit routers do not learn the derived /128 from this local route. Therefore this implementation does **not** satisfy multi-hop bootstrap reachability, and the integration gate remains FAIL.
- **Remaining limitation:** This route is a lab bootstrap mechanism only. It is not a production WAN reachability design. A separate, explicitly specified and authenticated transit-route distribution or encapsulation design is required before multi-hop lab success can be expected. Do not add transit routes from unauthenticated M1 data or CA metadata alone.
