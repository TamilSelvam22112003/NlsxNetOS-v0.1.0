# NLS vIP binding table and LSDB synchronization contract

## Purpose

NLS keeps temporary vIP and directional SourceToken values separate from the
router's stable original IP. After a successful, mutually authenticated NLH2
M1–M4 exchange (including signed Router-CA records and key confirmation), the
router publishes a session-scoped binding:

- `vip`: current temporary identity / row key;
- `original_ip`: Router-CA-authorized stable router address;
- `router_id` and `identity_public_key`: authenticated router identity;
- `source_token` and optional `send_token`: session-specific directional data-plane identifiers;
- `session_id`, `record_seq`, state and expiry: lifecycle/freshness context.

Before acceptance, a bootstrap vIP is `PENDING`, unauthenticated, and is never
exported by `nls.lsdb.export_records()` or returned by the authenticated
original-IP resolver. An accepted session can enter `OVERLAP` during rekey;
the new `ESTABLISHED` row is preferred for original-IP resolution while the old
row remains until session-scoped withdrawal/cleanup.

## LSDB export/import

`export_records()` emits deterministic version-1 `nls_vip_binding` records
only for unexpired authenticated `ESTABLISHED` or `OVERLAP` entries.
`import_record(record, authenticated_router_id=...)` requires the caller to
supply the identity authenticated by its routing control channel. It rejects
unknown/missing fields, mismatched router identity, expired records, unsupported
states, and invalid addresses. The record's own `router_id` field is not proof
of identity.

Withdrawals use `withdrawal_record()` before local deletion and
`apply_withdrawal()` at the receiving router. A withdrawal is bound to both
the authenticated router identity and the session id, so delayed teardown for
an old rekey session cannot delete the replacement session's row. Expiry is a
fallback when an explicit withdrawal is lost.

## Critical integration boundary

This commit defines the safe table record contract and unit-level lifecycle API.
It does **not** encode or flood OSPFv2/OSPFv3 LSAs, mutate FRR's native LSDB, or
advertise original-IP reachability through a running routing daemon. Those
operations require an explicit routing-protocol adapter and a wire-format /
authentication design for carrying NLS records in that plane. Until that adapter
is implemented and live multi-router tests prove propagation and withdrawal,
the feature is a local table plus serialization API—not network-wide LSDB
convergence. Import/export methods must only be called by a trusted adapter;
do not expose them as an unauthenticated socket or CLI operation.

## Acceptance criteria for routing integration

1. No pending, expired, revoked, or unverified binding appears in exported or
   imported routing state.
2. The authenticated channel identity equals the record's router identity.
3. Duplicate original-IP ownership by distinct router identities and SourceToken
   collisions fail closed.
4. New accepted session supersedes old session for lookup while old session can
   remain in overlap for packets in flight.
5. Withdrawal applies only to the exact router and session; duplicate withdrawal
   is idempotent.
6. Full two-router and six-node labs show an LSDB mapping after handshake, show
   no mapping before M4, and converge after rekey, session timeout and revocation.
7. WAN captures prove only the intended outer routing fields are visible and the
   original inner source address is absent from transit packets.
