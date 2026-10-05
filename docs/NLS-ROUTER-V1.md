# NLS Router v1

Experimental NLS Router engine for NlsxNetOS v0.1.0.

Implemented: persistent Ed25519 router identity; signed NLS session-init and response; ephemeral X25519 key agreement; transcript-bound HKDF-SHA256; directional session keys; AES-256-GCM UDP data; session-bound wire header; timestamp freshness; replay window; optional Linux TUN interface; local Router-CA consistency check; NLS identity/status CLI; unit tests.

The Router-CA remains an external registration/lookup authority. Its server/API contract is not defined in this repository, so no undocumented HTTP API is invented here.

Limitations: certificate issuance/revocation, automatic neighbor discovery, automatic TUN route installation, multi-peer prefix routing, and automatic rekeying are not implemented. The Python datapath is experimental, not production-performance code.

Packet flow: IP packet -> TUN -> NLS AES-GCM -> UDP/4789 -> peer NLS -> AES-GCM -> peer TUN.
