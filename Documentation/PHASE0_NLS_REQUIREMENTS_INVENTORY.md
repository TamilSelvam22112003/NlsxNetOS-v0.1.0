# Phase 0 — NLS Requirements Inventory (R1–R14)

**Inspected baseline:** `main` at `f6a3486a1aa4c4562191b2e37d8f382e0e6f3fe9` (router) and the paired CA baseline `bdfbda6a9d6c293307851eeb70e858bc55ae3295`.  
**Scope:** source-code inspection only. No protocol code was changed for this phase. Test suites were inspected but not executed from this GitHub-only review; no test result is asserted here.  
**Status definitions:** Implemented = code directly satisfies the normative requirement; Partial = some related mechanism exists but one or more normative conditions are missing; Missing = no implementation found for the required behavior.

## R1–R14 inventory

| Requirement | Status | Evidence in current source and gap |
|---|---|---|
| **R1 Router authentication** | **Partial** | Router: `nls/handshake.py:sign, verify, responder_key, initiator_key` signs/verifies INIT/RESPONSE using Ed25519 and checks certificate-shaped fields against configured Router-CA entries. `nls/daemon.py:_peer_trusted, _peer_for_obj` check local YAML trust entries and endpoint bindings. CA: `src/nls_nexos_core/control.py:NLSControlServer._authorize_client_certificate` validates real X.509 certificates for the TCP control channel. The UDP NLS handshake does not carry/validate the CA-issued X.509 certificate or a CA-signed live registry record; it relies on self-described fields plus local static trust metadata. |
| **R2 Temporary vIP as outer source, fresh/session-scoped, 10 s TTL** | **Partial** | `nls/handshake.py:new_init` generates a private-looking IPv6 string using random hex components and places it in signed handshake JSON. `nls/daemon.py:_send_init` calls `sendto` without assigning/binding that vIP as the OS outer source. No configured `vip.pool`, SHA-derived 128-bit address generation, 10-second TTL, interface add/remove, or post-expiry packet filter exists. |
| **R3 M1 source public keys encrypted to destination CA-record RSA key** | **Missing** | `nls/handshake.py:new_init` creates a signed JSON INIT with identity/DH fields; it does not hybrid-encrypt M1 with RSA-OAEP-SHA256 plus AES-256-GCM. RSA helpers in `nls/rsa.py:wrap_key, unwrap_key` exist, but are used by the data encapsulation path, not M1. |
| **R4 M2 encrypted to source key with destination cert, gateways, SA proposals, DH, nonce, IKE metadata** | **Partial** | `nls/handshake.py:responder_key` returns a signed RESPONSE containing responder identity, ephemeral DH value, session ID, timestamp, vIP/original IP, and INIT digest. It has no M2 hybrid encryption, destination X.509 certificate, gateway IP list, SA proposal/selection, responder nonce, or IKE metadata. |
| **R5 Switch to real WAN endpoints; remove vIP and drop later vIP packets** | **Missing** | `nls/daemon.py:_bind, _handle_response, _handle_init, run` use a socket bound to configured listen address and peer endpoints. No vIP address assignment, endpoint transition state, vIP removal, or post-switch drop rule exists. `nls/lsdb.py` retains vIP-to-original-IP metadata with an expiry, which is not the required interface/source lifecycle. |
| **R6 Source cross-checks M2 against signed CA record; reject mismatch/revoked/expired; send M3** | **Partial** | `nls/handshake.py:initiator_key` verifies the RESPONSE signature, session ID, timestamp, vIP/original IP, and INIT digest; `nls/daemon.py:_handle_response` checks the UDP source endpoint. There is no CA lookup per handshake, signed full-record comparison, certificate validity/revocation check in the UDP handshake, or M3 stage. CA `api.py:handle_control_request` supports enrollment/sync/heartbeat/status, not router-record lookup. |
| **R7 Destination validates M3 against CA and returns authenticated M4** | **Partial** | `nls/handshake.py:responder_key` checks INIT fields against locally configured trust values, and `nls/daemon.py:_handle_init` checks the peer. The implementation has no M3, no live CA record validation of M3, and no M4 trust acknowledgement/transcript confirmation. |
| **R8 Derive data session keys from both DH values, both nonces, Router-IDs, transcript hash** | **Partial** | `nls/handshake.py:derive_session` derives directional keys from one X25519 shared secret using HKDF-SHA256, but salt/info bind session ID and public identity bytes—not both nonces, both Router-IDs, and the M1–M3 transcript as specified. |
| **R9 Tunnel-mode AES-256-GCM encryption of entire client packet/source IP using directional session keys** | **Partial** | `nls/encapsulation.py:seal_ip_packet, open_ip_packet` encrypts the full inner packet with AES-256-GCM, so the inner source address is in ciphertext. However, it creates a random AES key per packet and wraps it with destination RSA-OAEP; the derived handshake directional keys are not used by this data path. Outer IP headers remain OS-generated and visible. |
| **R10 Tampered packets dropped** | **Partial** | `nls/encapsulation.py:open_ip_packet` relies on AES-GCM tag verification; `nls/daemon.py:_handle_data` catches errors and drops the packet. Existing unit tests include ciphertext/header tampering. The complete normative protocol and wire-level test are absent. |
| **R11 Destination decrypts and forwards inner packet** | **Partial** | `nls/daemon.py:_handle_data` decrypts and writes the inner packet to TUN; `_send_payload` encapsulates packets from TUN. The existing namespace integration tests exercise traffic under the current design, but do not verify the requested M1–M4/vIP protocol. |
| **R12 Sequence + 128-packet sliding replay window; no accepted packet repeated** | **Partial** | `nls/replay.py:ReplayWindow` implements a sliding bitmap and `nls/daemon.py:_handle_data` checks/marks sequence after authenticated decryption. The configured default is 64 in `nls/config.py:NLSConfig` and `config/nls/nls.yaml`, not 128. No rekey threshold/one-hour rekey implementation exists. |
| **R13 Silent wire failure, structured local reason codes, no secrets in logs** | **Partial** | `nls/daemon.py:_handle_init, _handle_response, _handle_data, _send_payload` generally drop on exceptions and log local warnings. Logs are free-form strings, not structured reason codes; exceptions are logged directly and include peer/network context. A systematic secret-redaction and failure-code contract is absent. |
| **R14 Router-CA issues/revokes certs and signed lookup(Router-ID) record with keys/endpoints/gateways/serial/status** | **Partial** | CA: `src/nls_nexos_core/ca.py:CertificateAuthority.enroll`, `database.py:Registry.get_router, get_certificate, revoke_certificate, list_revoked_certificates`, `cli.py:revoke_certificate`, and `api.py:_bundle` provide issuance, revocation, registry access, and revocation synchronization. There is no authenticated `lookup(Router-ID)` response containing both public keys, WAN IP, gateway IPs, serial/status, signed by the CA signing key. Existing router trust data is a local YAML file (`security/trust/router_ca/store.py`). |

## Required automated tests — baseline coverage observed

| Requested test | Baseline observation |
|---|---|
| Valid end-to-end handshake and client/server traffic | Related current-design coverage exists in `tests/integration/test_four_node_nls.py` and `tests/integration/test_ten_router_ipv6_chain.py`; it does not test the normative M1–M4 design. Not run in Phase 0. |
| Wrong certificate / revoked / expired router | Identity/signature and local CA-binding rejection tests exist (`tests/unit/test_nls_handshake.py`, `tests/security/test_protocol_fuzz.py`); dedicated X.509 wrong/revoked/expired NLS-handshake tests were not found. |
| CA mismatch in S3/S4; forged CA response | Not found. |
| Tampered ciphertext | Related tests exist in `tests/unit/test_nls_encapsulation.py`; not run in Phase 0. |
| Replayed packet | Related tests exist in `tests/unit/test_nls.py`, `tests/unit/test_nls_data.py`, and `tests/security/test_protocol_fuzz.py`; normative window size/packet path remains unverified. |
| Out-of-window packet | No dedicated normative NLS integration test found. |
| vIP reuse after expiry; vIP never seen after switch | No test proving interface address lifecycle or pcap outer-source transition found. `tests/unit/test_nls_lsdb.py` tests only metadata expiry. |
| SA downgrade; out-of-order handshake messages | Not found for M1–M4. |
| CA unreachable (fail closed) | The NLS UDP daemon requires configured local trust metadata; there is no per-handshake CA lookup/fail-closed behavior to test. |
| Rekey | No data-plane rekey test or implementation found. |
| pcap proves inner packet/source never plaintext on wire | No pcap assertion found. Existing encapsulation tests inspect payload/header bytes, not captured wire traffic. |

## Existing behavior and compatibility constraints observed

- NLS default configuration is disabled: `config/nls/nls.yaml`; runtime exits when disabled in `nls/daemon.py:run`.
- NLS activation is guarded by active local Router-CA entries and an enabled WAN-role interface: `nls/activation.py:activate`.
- Router-CA local records are YAML-backed and require an identity key, endpoint, and RSA encryption key for `nls_ready`: `security/trust/router_ca/models.py:RouterCAEntry.nls_ready`.
- The IOS-like CLI lives in `tools/router_cli/commands.py`; FRR administration is separate and must not be changed.
- Systemd NLS daemon runs as the `nlsxnetos` user with `CAP_NET_ADMIN` and TUN access: `config/systemd/nls-router.service`.
- Existing integration tests include root/network-namespace-dependent cases and an optional FRR check. Their results have not been run or asserted during this source inspection.

## Phase 0 conclusion

**No R1–R14 requirement is fully implemented as specified.** Several primitives exist, but the normative stages M1–M4, real outer-source vIP lifecycle, authenticated live CA lookup, data-plane session-key use, required replay/rekey parameters, structured failure reasons, and pcap proof are missing or partial.

**Gate status: Phase 0 inventory prepared; test baseline not executed.** Do not begin Phase 1 until this inventory and the test-execution plan are accepted. Keep the protocol labeled experimental.
