# NLS Product Blueprint

This document presents the two NLS repositories as one product. It is an
implementation blueprint, not a claim that NLS replaces TLS, IPsec, or the
Internet routing standards. NLS uses ordinary IP routing to reach an NLS
endpoint, then protects the original client/server packet inside its own
authenticated encryption boundary.

## Product boundary

| Component | Repository | Responsibility |
| --- | --- | --- |
| Router runtime | `NlsxNetOS-v0.1.0` | Linux/FRR integration, NLS UDP data plane, local identity material, TUN routing, router CLI and local Router-CA cache. |
| Router-CA core | `Nls-NexOS-Core-v0.1.0` | Authorized enrollment, X.509 identity certificates, revocation state, policy synchronization and audit records. |
| Existing network | External | IP reachability and routing (including OSPF/OSPFv3/BGP where deployed). It is not replaced by NLS. |

NLS has three deliberately separate planes:

```text
Routing plane:  WHERE can an outer packet go?
    FRR / Linux routes / OSPF / BGP / LSDB

Trust plane:    WHO is the destination NLS router?
    Router-CA enrollment / certificates / pins / policy / revocation

Data plane:     WHAT client traffic is carried?
    TUN -> NLS UDP -> authenticated encrypted inner IP packet
```

Keeping these concerns separate avoids an incorrect design in which an
encrypted outer destination address is expected to remain routable by ordinary
routers. The outer transport destination remains visible when normal IP
forwarding needs it; original client and server addressing remain inside the
protected inner packet.

## Deployment sketch

```text
                         management/control network
  +--------------------+ TCP 4790 +-------------------------+
  | NlsxNetOS router A |----------| Nls-NexOS Router-CA core |
  +--------------------+          +-------------------------+
          |                                    |
          | policy, issued identity certificate | registry, CA keys,
          | and revocation state                | audit database
          v                                    v

  Client LAN -- Router A -- normal routed WAN -- Router B -- Server LAN
                    \                             /
                     \------ UDP 4789 / NLS ------/

   The routed WAN carries the visible outer NLS transport packet.
   Router B alone decrypts the protected original client-to-server IP packet.
```

Every router retains its own private keys. A Router-CA is a trust and control
service, not a hop for user traffic.

## Lifecycle

### 1. Provision and enroll

1. An operator installs the Router-CA root certificate, Router-CA Ed25519
   control-key pin and enrollment credentials on the router through an
   out-of-band trusted channel.
2. The router creates its Ed25519 identity key and CSR locally. Its private
   key never leaves the router.
3. The router establishes the pinned NLS control handshake, then submits its
   CSR and one-time enrollment materials in an encrypted record.
4. Router-CA validates registration, credentials, CSR proof-of-possession,
   freshness and replay state before issuing an identity certificate.
5. Subsequent control connections are mutually authenticated and synchronize
   versioned policy plus certificate-revocation state.

The control channel is TCP 4790 by default. It is distinct from NLS user data.

### 2. Establish an NLS data-plane session

1. Linux routing sends a remote protected prefix to `nls0`.
2. Router A selects the most-specific Router-CA registry entry for the inner
   destination and checks the registered destination identity and endpoint.
3. Routers exchange signed NLS handshake messages, make fresh X25519 key
   agreement and derive directional session keys with transcript-bound
   HKDF-SHA-256.
4. A verified session becomes eligible to carry packets. Invalid identities,
   endpoint mismatches, replayed handshakes and failed authentication are
   rejected.

### 3. Carry client/server traffic

```text
Client IP packet
  -> nls0 on Router A
  -> choose Router B registration by longest prefix
  -> fresh AES-256 key encrypts the whole original IP packet with AES-256-GCM
  -> Router B RSA public key wraps that AES key with RSA-OAEP/SHA-256
  -> NLS UDP packet crosses the ordinary routed WAN
  -> Router B verifies bindings/freshness, unwraps and authenticates
  -> nls0 on Router B -> ordinary destination LAN route -> server
```

The return packet follows the same model with its own direction and session
state. The complete NLS header is associated data, so a change to its bound
metadata makes AEAD verification fail. Replay windows and timestamp checks
reject old or duplicate packets.

## What is protected and what remains visible

| Property | NLS treatment |
| --- | --- |
| Original client IP, original server IP, L4 headers, application payload | Encrypted and authenticated inside the NLS inner packet. |
| Outer WAN destination and UDP transport headers | Visible as required for normal IP forwarding. |
| NLS session identifier, sequence and timestamp | Visible but authenticated as AEAD associated data and validated by the receiver. |
| Router private keys and transient symmetric keys | Local only; never distributed as plaintext by Router-CA. |

## Tables and verification state

NLS does not replace the routing LSDB. FRR/OSPF/OSPFv3 owns topology and
next-hop calculation. The NLS daemon maintains an expiring **VIP Table** for
temporary identity bindings and an expiring **Trust Table** for only those peer
records that match the local Router-CA registry. During every new session, the
signed router-provided record must exactly match the Router-CA record's ID,
Ed25519 public key, endpoint and RSA encryption public key. See
[NLS Tables](nls/tables.md) for the table schema and full verification flow.

## Repository map

### NlsxNetOS

- `nls/`: handshake, identity, encryption, replay checks, TUN integration and
  packet daemon.
- `security/trust/router_ca/`: local authoritative destination registration
  and longest-prefix lookup used by the data plane.
- `nls/ca_client.py`: enrollment and persistent Router-CA policy/revocation
  client.
- `services/router/` and `tools/router_cli/`: router configuration and
  operator experience.
- `tests/`: unit, security, four-node and ten-router integration coverage.

### Nls-NexOS Core

- `src/nls_nexos_core/ca.py`: enrollment authorization, issuance, revocation
  and audit operations.
- `control_protocol.py`: the experimental encrypted NLS control record
  protocol.
- `database.py`: persistent router/certificate/replay registry.
- `api.py` and `cli.py`: service operations.
- `tests/`: unit, security and cross-repository control integration coverage.

## Operational acceptance criteria

Before any non-laboratory rollout, an operator should verify all of the
following on the actual Linux target:

1. `nlsxnetos doctor`, `nlsxnetos frr validate`, `nlsxnetos nls self-test` and
   `nlsxnetos router-ca validate` succeed.
2. Each Router-CA registration includes a valid destination prefix, endpoint,
   Ed25519 public key and RSA encryption public key.
3. The control identity pin and CA root were provisioned out-of-band and match
   the Router-CA service.
4. End-to-end, return-path, loss/reordering, revocation and failover tests run
   in a network topology representative of deployment.
5. The target's MTU leaves room for UDP, NLS and RSA-wrapped-key overhead;
   NlsxNetOS validates this when binding the data plane.

## Production statement

NLS is implemented as an experimental, production-integrated reference
product. It deliberately does not claim equivalence or superiority to TLS,
IPsec, OSPF or BGP. The custom NLS control protocol and data-plane design still
require independent cryptographic review, formal versioning, hostile-network
interoperability testing and target-hardware performance/fault testing before
they are appropriate for critical or untrusted production networks. HSM/TPM
protection, high availability, automated certificate renewal, signed CRL/OCSP,
administrative authentication/rate limiting and multi-host deployment testing
remain explicit release gates.
