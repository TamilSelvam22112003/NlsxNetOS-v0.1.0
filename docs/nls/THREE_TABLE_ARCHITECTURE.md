# NLS Router: VIP Table, Trust Table, and LSDB

This document defines the three logical control-plane tables. It does not change
the NLH2 wire format or make Router-CA metadata an automatic route source.

## 1. VIP Table

The `VIPVerificationTable` is a short-lived handshake staging table. It stores
the candidate vIP, session ID, destination router identity, original IP,
certificate DER and Ed25519 SPKI DER, record sequence, expiry, and the
cross-verification result. A staged row is `PENDING` and cannot authorize
forwarding. It becomes `VERIFIED` only when the destination-presented RDR and
independently verified Router-CA RDR match on the stable identity fields and
the handshake peer/signature checks succeed.

The bootstrap vIP is temporary. Once M4 and the endpoint-switch rules complete,
the bootstrap vIP is retired and removed from the kernel/LSDB bootstrap state.
The verified destination identity is represented by an active session and
authenticated directional SourceToken bindings, not by retaining the bootstrap
vIP as a route.

## 2. Trust Table

`TrustTable` is a separate session-scoped authorization table. It accepts
only a `VERIFIED` VIP row and independently checks the recorded cross-verification
flags, equality of destination-vs-CA original IP/certificate/public key values,
and certificate/SPKI fingerprints. It records the router ID, original IP,
session ID, record sequence, fingerprints, verification time, bounded trust
lease, and `TRUSTED` state.

The Trust Table does not persist raw certificates, public-key blobs, private
keys, or traffic-encryption keys. Raw session keys are never copied into a
table. Session keys are derived through the authenticated X25519/HKDF handshake.

A handshake cannot finish activation unless the Trust Table accepts the
verified VIP row. Handshake abort, timeout, trust lease expiry, Router-CA
freshness/revocation teardown, and session deletion remove the matching
session-scoped trust entry. Removing an old session must not delete a newer
session created during rekey.

## 3. LSDB

The LSDB stores control-plane reachability bindings and SourceToken mappings.
Bootstrap entries are explicitly unauthenticated and are never valid for
original-IP resolution or forwarding. Only authenticated session bindings can
be published as `ESTABLISHED` or `OVERLAP`. Updates must pass schema,
identity, state, expiry, and sequence checks. Withdrawals and cleanup are scoped
to the session ID so stale cleanup cannot delete a replacement session's row.

The LSDB is not a substitute for Trust Table authorization, and Router-CA
metadata alone must never install kernel routes.

## Lifecycle contract

1. Stage a temporary VIP candidate as `PENDING`.
2. Independently verify destination-router and Router-CA records and handshake proofs.
3. Promote the VIP staging row to `VERIFIED` only on exact stable-identity match.
4. Record `TRUSTED` authorization in the Trust Table.
5. Complete handshake key confirmation; activate the session and publish authenticated LSDB bindings.
6. Retire/release the bootstrap VIP. Use derived session keys and directional SourceTokens for secured data traffic.
7. On abort, revocation, expiry, rekey overlap completion, or session teardown, remove only the rows belonging to that session ID.

## Security invariants

- A VIP-table row alone never authorizes forwarding.
- Any identity mismatch or invalid/stale trust proof fails closed.
- The Trust Table stores fingerprints and verification evidence, not traffic keys.
- No active session may outlive its Trust Table authorization lease; expiry tears down the session.
- A stale withdrawal or cleanup operation must not delete a newer session's mapping.
- These are code-level invariants; end-to-end propagation through a routing protocol
  still requires separate integration tests.
