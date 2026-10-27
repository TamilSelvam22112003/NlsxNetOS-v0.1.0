# Changelog

## Unreleased

- Initial project scaffold.

## Unreleased — destination-preserving NLS workflow

- Hardened relay processing with strict configured NLS UDP source-port checks and ingress-interface validation.
- Restricted NLS TPROXY interception to the configured WAN interface.
- Documented how the draft runtime aligns with the attached source-metadata confidentiality workflow, including the separation between router hop-session X25519/HKDF and current per-packet RSA-OAEP endpoint wrapping.
- Kept the profile feature-gated and draft-only pending live WAN packet captures, endpoint return-path proof, and MTU/ICMPv6 acceptance.

## Unreleased — endpoint-session integration

- Integrated the endpoint agent with signed NLEH control messages and NLE3 AEAD data packets using ephemeral X25519 and HKDF-SHA-256 session keys.
- Added router-side handling for endpoint-session responder handshakes and a correlated return path for endpoint-agent handshake responses over the authenticated relay session.
- Added endpoint-agent-initiated session response delivery through the registered Router-CA endpoint identity.
- Fixed the endpoint identity-binding regression test so it tests a validly targeted but unexpected responder identity rather than an INIT that must fail at the responder first.
- CI and live multi-router acceptance remain pending for the latest integration head.
