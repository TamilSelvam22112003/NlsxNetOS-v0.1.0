# Changelog

## Unreleased — Prompt 2

- Added Router-CA client verification for canonical-CBOR signed RDRs and directory bundles, including signed nonce checks, expiry, rollback rejection and atomic verified-cache persistence.
- Added `trust_mode: ca|offline` and `stale_grace_seconds: 0` configuration.
- Added `nlsxnetos router-ca import FILE` for signed offline bundles.
- Replaced the unsigned YAML Router-CA trust path with a signature-verified directory cache.
- Exposed directory freshness and certificate revocation accessors for later daemon integration.

- Converted the Prompt 1 forged-CA-response and CA-unreachable strict-xfail cases into passing client-verification tests; 21 handshake/data-plane strict xfails remain assigned to later prompts.
- Prompt 2 router/client gate passed in CI run 38862159980 on Ubuntu 22.04 and 24.04.
