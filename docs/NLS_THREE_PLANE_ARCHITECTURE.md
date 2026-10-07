# NLS Three-Plane Architecture

NLS separates routing, trust/session establishment, and protected packet transport into three logical planes.

## 1. Routing Plane

The routing plane determines **WHERE traffic should go**.

- OSPF / OSPFv3
- Neighbor discovery
- Topology discovery
- Link-State Database (LSDB)
- SPF calculation
- Route convergence
- FIB/RIB generation

Router-CA information may be associated with routing destinations, but Router-CA trust validation is performed by the trust/session plane.

Conceptual flow:

```text
OSPF / OSPFv3
      |
      v
Topology / LSDB
      |
      v
SPF calculation
      |
      v
Routing table / FIB
      |
      v
NLS forwarding decision
```

## 2. Trust / Session Plane

The trust/session plane determines **WHO is trusted and how a secure NLS session is established**.

- Router-CA registry/trust metadata
- Router identity validation
- Temporary identity handling
- Destination-router validation
- X25519 key exchange
- HKDF session-key derivation
- Mutual authentication
- NLS session establishment

Router-CA answers the trust question; OSPF answers the path-selection question.

Conceptual flow:

```text
Destination route available
        |
        v
Destination router identity
        |
        v
Router-CA validation
        |
        v
X25519 key exchange
        |
        v
HKDF session-key derivation
        |
        v
Mutual authentication
        |
        v
NLS session established
```

## 3. NLS Data Plane

The data plane transports the actual client/server traffic.

Only the forwarding information required by the NLS forwarding mechanism is exposed to intermediate routers. The original IP packet is protected using a hybrid RSA + symmetric construction. A fresh AES-256 data key is generated for each NLS packet. AES-256-GCM encrypts and authenticates the original IP packet, while RSA-OAEP with the destination router's public key protects the AES data key.

```text
NLS DATA PACKET

+---------------------------------------------+
| Outer forwarding / transport information   |
|                                             |
| Destination = visible forwarding endpoint   |
+---------------------------------------------+
| NLS / UDP metadata                          |
|                                             |
| Session ID                                  |
| Sequence number                             |
| NLS flags / forwarding metadata             |
+---------------------------------------------+
|                                             |
|       AES-256-GCM CIPHERTEXT                |
|                                             |
|   +-------------------------------------+   |
|   | Original IPv6/IP packet              |   |
|   |                                     |   |
|   | Source      = client IP       [LOCK] |   |
|   | Destination = server IP      [LOCK] |   |
|   | TCP/UDP                     [LOCK] |   |
|   | Application payload         [LOCK] |   |
|   +-------------------------------------+   |
|                                             |
+---------------------------------------------+
| RSA-OAEP wrapped AES-256 data key           |
+---------------------------------------------+
| AES-GCM authentication tag                  |
+---------------------------------------------+
```

Intermediate NLS routers should forward the NLS packet without decrypting the original inner IP packet.

## Hop-by-hop forwarding

The logical NLS destination may identify the forwarding destination/next NLS endpoint while the original client/server addressing remains inside the encrypted packet.

```text
Client -> Ra -> Rb -> Rc -> Rd -> Server

Inner protected packet:
    Client ----------------------------> Server
                 [AES-GCM]

Forwarding decisions:
    Ra -> Rb
    Rb -> Rc
    Rc -> Rd
```

The routing plane can recalculate paths when links or routers fail. The data plane then uses the updated forwarding information.

Example:

```text
Initial:
Ra -> Rb -> Rc -> Rd

If Rc fails:
Ra -> Rb -> Rf -> Rg -> Rd

If Rf also fails:
Ra -> Rb -> Rh -> Ri -> ... -> Rn -> Rd
```

The protected original packet does not need to be decrypted at each intermediate router merely to make the next-hop decision. The destination router alone needs the RSA private key for final data-plane decryption.

## Temporary Identity

A temporary NLS identity may be represented as a fixed-format hexadecimal identifier.

SHA-256 produces:

```text
256 bits = 32 bytes = 64 hexadecimal characters
```

If the current experimental format requires 128 hexadecimal characters, the 64-character representation may be repeated:

```text
Temporary-ID = SHA256(input) || SHA256(input)
```

This produces:

```text
128 hexadecimal characters = 64 bytes = 512 bits of representation
```

**Important:** repeating the same SHA-256 value does not increase cryptographic entropy from 256 bits to 512 bits. The identifier should therefore be treated as a 128-character protocol identifier, not as a 512-bit-security cryptographic primitive.

For a production protocol, a random or cryptographically derived unique identifier should be preferred and its collision/rotation properties specified explicitly.

## Security boundary

NLS should distinguish between:

### Visible to forwarding infrastructure

- Information required by the underlying network to transport the NLS packet
- NLS forwarding destination/endpoint as required by the selected forwarding model
- Required NLS session/sequence metadata

### Protected by NLS

- Original client/source IP
- Original server/destination IP
- TCP/UDP information
- Application payload
- Any other inner-packet fields included in the AES-GCM plaintext

The underlying IPv6/UDP transport header cannot have its IPv6 source field selectively encrypted while remaining an ordinary routable IPv6 header. Therefore, source-address privacy in NLS must be defined in terms of **original/inner source identity** versus the **outer transport endpoint**, and any stronger hop-to-hop source concealment requires an explicit relay/re-encapsulation design.

## Design principle

NLS therefore separates three questions:

```text
ROUTING PLANE
    WHERE?
      |
      v
TRUST / SESSION PLANE
    WHO + HOW TO TRUST?
      |
      v
DATA PLANE
    WHAT IS TRANSPORTED?
```

This separation is fundamental to the NLS architecture.


## RSA Hybrid Protection

The NLS data-plane packet follows this development design:

```text
Original IP packet
      |
      v
Fresh random AES-256 data key
      |
      +---- AES-256-GCM ----> encrypted original IP packet + authentication tag
      |
      +---- RSA-OAEP -------> destination router RSA public key protects AES data key
      |
      v
NLS packet
  visible destination metadata
  NLS session/sequence metadata
  RSA-wrapped AES-256 data key
  AES-256-GCM ciphertext
  GCM authentication tag
```

RSA is deliberately used only for key protection. The original IP packet is not directly RSA-encrypted. The destination router loads its local RSA private key and performs the reverse operation. A router that only forwards the outer NLS transport packet does not need the destination private key.

The current implementation uses RSA 3072-bit keys with RSA-OAEP/SHA-256 and fresh 256-bit AES data keys with AES-256-GCM. Router-CA entries can carry the destination router's RSA public key in the `encryption_public_key` field.

The 128-hex-character temporary identity remains an experimental identifier format. Its cryptographic-strength analysis is intentionally deferred to a later protocol-design phase.
