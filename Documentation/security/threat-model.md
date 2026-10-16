# NLS v1 threat model and verification findings

This is a source review and target specification, not a penetration test or cryptographic audit. Current runtime has known gaps; no production-security claim is made.

Assets include router identity/RSA keys, CA keys, credentials, registry, certificates/RDRs, revocation state, ephemeral/session keys, replay state, inner packets, route policy and vIP lifecycle. Boundaries: router UDP, CA TCP 4790, operator config, kernel TUN/routes and CI. Adversaries may observe/inject/replay/reorder/modify packets, spoof outer sources where possible, operate rogue routers, replay stale CA responses, submit malformed handshakes, trigger RSA costs, exploit stale revocation, or control an authorized router.

## V1–V11 verification
| ID | Result | File:function evidence | Implication / test |
|---|---|---|---|
| V1 revocation persisted but not read by data plane | CONFIRMED | nls/ca_client.py:ClientSettings.load, _persist_bundle write file; nls/daemon.py:_handle_init/_handle_response/_handle_data do not read it. | Revocation can remain unenforced; test revoked router/session. |
| V2 self-asserted JSON cert; no CA lookup at handshake | CONFIRMED | nls/handshake.py:new_init builds dict; responder_key compares local values; daemon _send_init/_handle_init do not live-lookup or validate X.509 chain. | Cached YAML is not fresh signed RDR; test CA mismatch/expiry/revocation. |
| V3 derived send_key/recv_key unused for data | CONFIRMED | handshake.py:derive_session; daemon.py:Session/_handle_data; encapsulation.py:seal_ip_packet/open_ip_packet call rsa.py:wrap_key/unwrap_key per packet. | Sender-authenticated directional AEAD absent; test forgery. |
| V4 vIP only a string | CONFIRMED | handshake.py:new_init creates vip; daemon.py:_send_init/_bind/_handle_response do not assign/delete it or source from it. | No actual bootstrap/endpoint switch; test address and pcap. |
| V5 cleartext signed JSON | CONFIRMED | handshake.py:canonical/encode_message/decode_message/sign/new_init use JSON under NLSH. | Metadata visible; test pcap confidentiality. |
| V6 endpoint equality blocks NAT; WAN role | PARTIAL | daemon.py:NLSDaemon._send_init rejects a CA endpoint differing from the local source/listen endpoint (endpoint equality is confirmed); WAN-role enforcement is separate and not established as a complete prerequisite by the handshake path. | NAT/multihoming restricted; test endpoint mismatch and role configuration. |
| V7 forged high sequence can advance replay window | CONFIRMED under current construction/session-source constraints | daemon.py:_handle_data checks can_accept, opens packet, then marks; encapsulation.py:seal_ip_packet lets anyone with destination RSA public key create valid GCM packet with chosen seq. | Invalid AEAD alone does not poison, but forged valid-at-AEAD-layer packet can; require session AEAD test. |
| V8 destination public-key forgery accepted by opener | CONFIRMED at API boundary | encapsulation.py:seal_ip_packet/open_ip_packet; session_id/router_identity are public fields and caller wraps chosen AES key. | AEAD integrity is not sender identity; daemon checks still apply. |
| V9 RSA-3072 unwrap benchmark | CONFIRMED — benchmark run | encapsulation.py:open_ip_packet calls rsa.py:unwrap_key per packet; tests/benchmarks/benchmark_nls_rsa_unwrap.py measures decrypt-only OAEP unwrap. Ubuntu 24.04 GitHub runner, Python 3.12.3, cryptography 41.0.7, RSA-3072, 5 rounds x 100 iterations: median 2.0501 ms/unwrap, estimated 487.79 unwraps/s single core. | Environment-specific microbenchmark only; excludes parsing, AEAD, socket, routing and contention. Not an end-to-end throughput claim. |
| V10 malformed INIT can block mapped peer | CONFIRMED | daemon.py:_handle_init exception path remaps identity/source and calls _block; config.py:NLSConfig.peer_block_seconds defaults 60. | Garbage may block legitimate peer under spoofable/shared endpoint conditions; test source-based limiting. |
| V11 CA metadata can create routes | CONFIRMED | config.py:load imports CA entries/prefixes; daemon.py:run calls install_tun_routes; routing.py:install_tun_routes creates routes from allowed_prefixes. | Violates operator-only route creation; regression test required. |

## Threat/control matrix
| Threat | Required control | Planned test |
|---|---|---|
| MITM/impersonation | X.509 chain, signed fresh RDR, Ed25519 signatures, endpoint binding | wrong cert, forged CA, S3/S4 mismatch |
| Replay | session transcript, directional AEAD nonce, authenticate-before-mark 128-window | duplicate, out-of-window, poisoning |
| Downgrade | CA policy, single suite, minimum version | SA downgrade |
| Rogue CA response | pinned directory key, NLS-DIR-v1, nonce echo, freshness | forged/stale response |
| vIP abuse | random /128, interface assignment, TTL 10 s, switch only after M4 | expiry/reuse and pcap |
| DoS/amplification | padded M1, bounded state, 5 s timeout, per-source rate limit | amplification/garbage M1 |
| Revocation lag | signed revocation enforced at admission/refresh; fail closed stale | revoked router/CA unavailable |
| Inner source spoofing | D checks decrypted source against RDR prefixes | unauthorized inner source |
| Secret leakage | stable reason codes and no secret logs | log canary |
| Route injection | operator-only route creation | V11 regression |

Target: ca trust mode uses live lookup; offline is opt-in signed bundle and degraded freshness. Lookup <=30 s, bundle <=10 min, stale-grace=0, timeout=5 s, minimal state until M3, session AEAD, 128-window, rekey at 2^32 packets or one hour, operator-only routes. V9 benchmark remains unrun.

## Prompt 3 remediation status — 2026-10-16 (acceptance gate passed for implementation commit 471694a7946f)

The V1–V11 table above is the Prompt 1 source-evidence baseline, not a claim that every finding remains unchanged after Prompt 3. On `feat/nls-v1`, the active daemon handshake path now dispatches NLH2 M1–M4, verifies fresh signed Router-CA records at S3/S4, assigns and retires temporary vIPs, drops retired-vIP traffic, and no longer installs TUN routes from CA peer prefixes. Garbage unauthenticated handshake input is rate-limited by observed outer source and does not create identity-keyed blocks. These controls passed the Prompt 3 acceptance gate on implementation commit `471694a7946fa6c7ed98fa9f90aead09c9b43e98` (GitHub Actions run 38874400473).

Historical note (Prompt 1–3 baseline): V3 and V8 described the earlier NLE1 data path, which used per-packet RSA wrapping and was forgeable at the legacy opener boundary. Prompt 4a replaces that path with NLE2 directional-session AEAD, but this new implementation is not yet gate-accepted and must not be represented as secure or production-ready until exact-head CI, end-to-end traffic tests, lifecycle/rekey tests, measured benchmarks, and independent review pass. NAT traversal remains NOT VERIFIED. The vIP bootstrap path still requires IPv6 return routing to the temporary /128; deployment needs a routable delegated pool or equivalent explicit return routing.
