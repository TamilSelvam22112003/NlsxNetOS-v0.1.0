# NLS vIP Verification Table and LSDB Promotion

## Purpose

NLS has two separate data structures with different trust roles:

1. **Temporary vIP verification table** (`nls.vip_table.VIPVerificationTable`) holds a candidate identity while NLH2 M1–M4 is in progress.
2. **Authenticated NLS LSDB metadata** (`nls.lsdb`) holds an accepted original-IP-to-SourceToken/vIP identity binding for an established session.

A temporary row is not forwarding authority and must never be used to resolve an original IP. The verification table is intentionally separate from `nls.lsdb`.

## Temporary row

One row is scoped to a unique handshake session ID and contains:

| Field | Purpose |
|---|---|
| `vip` | Canonical IPv6 bootstrap vIP observed for the initiating router |
| `original_ip` | Canonical original IPv6 address from the signed Router Directory Record (RDR) |
| `router_id` | Router identity from the signed RDR |
| `certificate_der_b64` | Base64-encoded DER certificate, retained only during verification |
| `certificate_sha256` | Fingerprint used for an exact certificate comparison |
| `public_key_der_b64` | Base64-encoded DER SubjectPublicKeyInfo for the Ed25519 identity public key |
| `public_key_sha256` | Fingerprint used for an exact public-key comparison |
| `record_seq` | Monotonic Router-CA directory-record sequence |
| `session_id` | Handshake generation; all cleanup operations are session-scoped |
| `status` | `PENDING` until all comparisons pass, then `VERIFIED` |
| `expires_at` | Short lifetime capped at ten seconds |

The default file is `/run/nlsxnetos/vip-verification.json`, with mode `0600`. Override it for tests with `NLSXNETOS_VIP_VERIFY_TABLE`. It contains public identity material, not private keys, but is still restricted because it is transient trust state.

## Verification and promotion sequence

1. Verify the Router-CA-signed RDR and require `status=ACTIVE`, a fresh record sequence, an unrevoked certificate, and valid endpoints/policy.
2. Stage the vIP/original-IP/certificate/public-key tuple as `PENDING`. Do not use this row for forwarding or route selection.
3. Cross-check the peer-provided certificate, identity signature/public key, router ID, original IPv6 address, and record sequence against the current verified Router-CA record. M3 is also checked against the fresh S4 record; the initiator accepts M4 only after peer signature, transcript, and key-confirmation checks.
4. Change the row to `VERIFIED` only if both the Router-CA record and the destination-router handshake checks have succeeded and every stored field matches exactly. Any mismatch fails closed.
5. Only then can session activation publish the normal authenticated NLS LSDB records. Those rows retain operational fields such as router ID, original IP, identity public key, vIP/SourceToken, session ID, record sequence, state, and expiry. The temporary certificate bytes are removed when publication succeeds.
6. On timeout, abort, teardown, or failed activation, delete the temporary row. A cleanup operation is bound to the handshake session ID so an old handshake cannot delete a newer mapping.

## LSDB semantics

The NLS LSDB metadata is not the same thing as the native FRRouting OSPF/BGP link-state database. Its authenticated records support NLS lookup and synchronization; the current `nls.lsdb` serialization/import path does not itself originate OSPF LSAs or install kernel routes. Actual OSPF distribution requires a separately reviewed routing adapter and must not be implied by a local JSON row.

## Security invariants and test gates

- Pending rows are not exported by `nls.lsdb.export_records()` and cannot be treated as authenticated reachability.
- A certificate mismatch, public-key mismatch, original-IP mismatch, vIP/session mismatch, sequence mismatch, revoked/non-active RDR, or expired row prevents promotion.
- Certificate DER is transient; only the verified public-key/original-IP identity and session-specific addressing metadata remain in the LSDB.
- A successful unit test suite is necessary but not sufficient: the Ubuntu 22.04/24.04 six-node lab must prove both ends accept the same identity, the LSDB rows are present only after M4, timeout/mismatch cleanup works, WAN packet capture contains no original source-IP/certificate/plaintext leakage, and cProfile artifacts are generated.