# NLS implementation deviations

This file records intentional implementation differences from the normative protocol specification. It does not override the specification; each item requires reviewer approval before release.

## DEV-001 — Lab-only derived-vIP return route (superseded)

- **Status:** Superseded by the Stage 7 normative bootstrap-locator decision.
- **Historical implementation:** Stage 6 installed a temporary destination-side route for a derived vIP, using the kernel-selected next hop toward the authenticated source `originalIP`.
- **Observed limitation:** CI on 2026-10-25 showed that a destination-local route did not teach intermediate routers the arbitrary derived /128. Six-node and ten-router integration/return-path tests failed or timed out.
- **Current implementation direction:** Stage 7 uses the authoritative, routable WAN locator as the outer endpoint for NLH2 M1-M4. The derived vIP remains signed/sealed handshake context and is not assigned to an interface, advertised, or installed in the kernel FIB.
- **Security boundary:** M1-M4 outer peer locators must match the primary endpoint in fresh authenticated Router-CA records. The vIP digest and policy remain unchanged. The handshake outer header reveals the WAN locators; source-address-confidentiality claims apply only to the separately specified post-M4 SourceToken data plane.
- **Cleanup:** New handshake code does not create vIP addresses or routes. Legacy VIPManager startup recovery remains solely to remove stale addresses from installations that used the older implementation.
- **Release status:** Stage 7 code is a draft implementation. The six-node and ten-router tests must pass on the exact final commit, and captures must verify outer locator selection, before this design can be considered conformant.
