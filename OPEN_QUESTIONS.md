# Open Questions

## OQ-5A-001 — Ubuntu 24.04 enrollment failure's original exception (UNCONFIRMED)

**Status:** Unconfirmed historical root cause; do not treat the proposed explanation as proven.

The original Ubuntu 24.04 enrollment failure did not retain a complete traceback in the available CI evidence. The current source includes a UTC-aware certificate-validity compatibility correction in NlsxNetOS commit `ee4b734`, but without the original exception and failing input it is not possible to prove that this was the exact exception raised in the historical enrollment attempt.

**Evidence available as of 2026-10-17:**
- NlsxNetOS stabilization/profile head before the performance work: `6fe02238b10da005717abb68e5df3c17be9c9abe`.
- Router-CA branch `feat/nls-v1` head: `dbcadb92941b64125813b2955652f42ec7e3aff7`.
- Router-CA CI run `39013789493` completed successfully on that head. Both `test` and `cross-repo-control-integration` jobs passed on Ubuntu 22.04 and 24.04.
- Producer-side Ed25519 directory-key encoding correction is in Router-CA commits `eefb10431eee0b509d640a4f75d9debea749bcc2` and `79b66b26d365b400d0963a873768a752970715b1`. This is a separately identified key-encoding issue and should not be conflated with the unconfirmed enrollment exception.

**Closure condition:** capture a complete traceback and sanitized failing field/exception metadata if the enrollment failure recurs on Ubuntu 24.04, or add a deterministic regression test that reproduces the specific original exception. Until then, keep this question marked UNCONFIRMED.


## OQ-2026-10-25-001 — Amended vIP derivation and routability

The shared master spec requires a deterministic SHA-512-derived vIP based on the specified canonical fields, fresh 32-byte `vip_nonce`, 30-second `time_bucket`, and address-policy version. The reviewed runtime instead allocates a random /128 from a local pool. The spec also notes that the digest-derived /128 may not be reachable on a routed WAN and forbids rewriting digest bits to fit a pool.

**Safe interpretation:** implement the derivation exactly as specified; do not mask or rewrite output bits. Keep the lab-only temporary route behind the explicit lab configuration. Production routed-WAN bootstrap reachability remains blocked until a separately reviewed routing/encapsulation solution preserves the derivation.

## OQ-2026-10-25-002 — M1 padding and IPv6 MTU

The anti-amplification requirement pads M1 to at least the maximum permitted M2 size, while ordinary IPv6 links guarantee only a 1280-byte MTU. Large handshake datagrams may be fragmented or dropped by middleboxes.

**Safe interpretation:** do not reduce padding or change MTU/performance thresholds silently. Measure behavior on the existing six-node lab and representative constrained-MTU paths; document the supported deployment conditions.

## OQ-2026-10-25-003 — M4 loss and responder activation

The responder currently prepares and activates the session after sending M4, but cannot know whether the initiator received and accepted it.

**Safe interpretation:** do not treat UDP send success as proof of peer acceptance. Specify bounded M4 retransmission or a confirmation/recovery rule and test lost, duplicated and reordered M4 messages before declaring lifecycle conformance.

## OQ-2026-10-25-004 — NLD2 rollout boundary

The master spec requires NLD2 framing and explicit metadata modes without fallback, but the reviewed `feat/nls-v1` branch still emits the legacy counter-first SourceToken payload. A separate metadata-mode branch contains newer implementation work.

**Safe interpretation:** `feat/nls-v1` remains the target branch. Port and validate the NLD2 implementation there as a versioned, coordinated change; do not silently merge branches or enable fallback between wire formats.

## OQ-2026-10-25-005 — RDR exact-field validation

The current RDR validator enforces required v2 fields but does not explicitly reject all unknown fields.

**Safe interpretation:** reject unknown fields for the versioned RDR schema and add tests for unknown, missing, legacy and malformed fields before treating the schema as conformant.


## OQ-2026-10-25-006 — Canonical M1 public-key wire encodings

The minimal-M1 field list names `source_ed25519_pub` and `source_rsa_pub`, but the cited amendment does not explicitly state whether these fields carry raw key bytes, PEM, or DER SubjectPublicKeyInfo (SPKI).

**Safe implementation interpretation in Stage 6:** encode both fields as DER SubjectPublicKeyInfo, matching the authoritative RDR's Ed25519 SPKI representation and the canonical public-key representation used for the RSA key comparison. The responder compares the complete DER bytes against the fresh authenticated RDR before accepting the M1 signature. This is a draft implementation decision, not a claim that the ambiguity is already resolved normatively. Confirm the encoding in MASTER_SPEC.md before merging the Stage 6 PR; do not add wire-format fallback.

## OQ-2026-10-25-007 — Derived global-unicast vIP reachability

Stage 6 now derives and temporarily assigns a policy-v1 global-unicast vIP. It also implements an optional lab-only /128 return route, enabled only by both `deployment_mode: lab` and `vip.lab_temporary_route.enabled: true`; the flag defaults to false and config loading rejects it in production mode. Route ownership is persisted per router for cleanup on normal teardown and startup recovery.

This local lab route still does not prove upstream anti-spoofing acceptance, production WAN reachability, NAT/firewall compatibility or PMTU behavior.

**Safe interpretation:** keep this work in a draft branch. Do not approve production deployment until the bootstrap return path, source-address validation, route cleanup, firewall/NAT and PMTU behavior are tested in the target environment. No digest rewriting or private-pool fallback is permitted.
