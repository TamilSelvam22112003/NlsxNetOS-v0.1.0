# Changelog

## Unreleased

- Initial project scaffold.

## Unreleased — destination-preserving NLS workflow

- Hardened relay processing with strict configured NLS UDP source-port checks and ingress-interface validation.
- Restricted NLS TPROXY interception to the configured WAN interface.
- Documented how the draft runtime aligns with the attached source-metadata confidentiality workflow, including the separation between router hop-session X25519/HKDF and current per-packet RSA-OAEP endpoint wrapping.
- Kept the profile feature-gated and draft-only pending live WAN packet captures, endpoint return-path proof, and MTU/ICMPv6 acceptance.
