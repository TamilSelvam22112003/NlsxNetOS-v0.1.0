# NLS Tables

NLS uses three different tables. They have separate owners and must not be
merged, because routing information is not proof of router identity.

| Table | Owner and location | Purpose | Lifetime |
| --- | --- | --- | --- |
| Routing LSDB | FRR / OSPF / OSPFv3 | Neighbors, links, topology and path calculation. | Controlled by the routing protocol. |
| VIP Table | NLS daemon, `/run/nlsxnetos/nls-vip-table.json` | Short-lived virtual identity and the two identity records being compared during a handshake. | Expires with the NLS session. |
| Trust Table | NLS daemon, `/var/lib/nlsxnetos/nls-trust-table.json` | Only cross-verified destination bindings that are eligible to carry NLS traffic. | Expires with the NLS session and is re-verified for every new session. |

## Router-CA destination record

The Router-CA registry is the authoritative source for a destination record.
Each NLS-ready record contains:

```text
router_ca_id
destination prefix
destination endpoint
destination Ed25519 public key
destination RSA encryption public key
```

The current router implementation reads this record from its local
Router-CA-registry cache. The cache is provisioned or synchronized through the
trusted Router-CA control-plane process; it is not accepted from an unauthenticated
NLS packet.

## Cross-verification flow

1. Router A performs a longest-prefix lookup for the client packet's destination.
2. Router A obtains Router B's destination record from the local authoritative
   Router-CA registry cache.
3. Router A creates a temporary VIP and sends the signed NLS INIT message.
4. Router B validates Router A's signed Router-CA record against its own
   authoritative cache, then returns its own signed destination record.
5. Router A verifies Router B's signature and compares these exact fields:
   Router-CA ID, Ed25519 public key, endpoint and RSA encryption public key.
6. A mismatch rejects and temporarily blocks the peer. A match creates the
   VIP Table and Trust Table records, then permits protected data traffic.

The reverse direction uses the same procedure. The response itself is signed
by the claimed router identity, so altering the returned identity record also
breaks signature verification.

## Trust Table safety rule

The Trust Table is a cache of a successful verification, never the authority
for a new peer. Every new session starts with the Router-CA registry lookup and
cross-verification again. Expiry removes both temporary VIP state and Trust
Table state; a later connection cannot rely on stale entries.
