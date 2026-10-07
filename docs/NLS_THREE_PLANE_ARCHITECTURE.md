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
- RSA router-key authentication
- NLS session establishment
- Replay protection
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

Only the forwarding information required by the NLS forwarding mechanism is exposed to intermediate routers. For this development phase, the original IP packet is protected using RSA only. The packet is split into RSA-OAEP/SHA-256 blocks and encrypted directly with the destination router's RSA public key. The sender uses its RSA private key to create an RSA-PSS/SHA-256 signature over the NLS header and ciphertext. No AES data key, AES-GCM operation, or symmetric payload key is used.

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
| RSA-OAEP wrapped AES-256 data key           |
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
                 [RSA-OAEP]

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


## RSA-only data-plane protection

The current development data-plane packet uses only RSA cryptography:

```text
Original IP packet
       |
       v
Split into RSA-OAEP/SHA-256 plaintext blocks
       |
       +--> RSA-OAEP with destination router public key
       |
       v
NLS header + RSA ciphertext blocks
       |
       +--> RSA-PSS/SHA-256 signature with sender router private key
       |
       v
NLS packet
  visible destination metadata
  RSA ciphertext blocks
  RSA signature
```

For a 3072-bit RSA key with OAEP/SHA-256, one RSA block can carry at most 318 plaintext bytes and produces a 384-byte ciphertext block. This makes the RSA-only transport substantially larger and slower than a symmetric data plane. The implementation therefore validates the configured NLS TUN MTU against the WAN MTU and may require a smaller TUN MTU.

Each RSA-OAEP chunk is cryptographically bound to the NLS header and its chunk index through the OAEP label. The complete header and ciphertext are additionally authenticated with RSA-PSS/SHA-256.

The destination router uses its RSA private key to decrypt the chunks and the sender's registered RSA public key to verify the signature. Intermediate NLS routers forward the protected packet without possessing the destination private key.

**Development constraint:** AES payload encryption and RSA-wrapped AES data keys are disabled in this phase. The protocol is intentionally RSA-only until the next design phase.

## NLS router forwarding state machine

The router data path is explicitly divided into three operational cases:

### 1. LAN ingress

```text
LAN client packet
      |
      v
NLS LAN policy route
      |
      v
NLS TUN
      |
      v
Read original destination
      |
      +--> active NLS session --> AES-256-GCM + RSA-wrapped data key --> WAN
      |
      +--> no session
              |
              v
          Router-CA resolve
              |
              v
          validate destination router
              |
              v
          NLS handshake
              |
              v
          establish session
              |
              v
          encrypt + forward
```

The router does not need a preconfigured static peer for every destination when an external Router-CA is available.

### 2. WAN ingress for a packet destined to this router

The NLS forwarding destination in the visible NLS header is checked first. If it belongs to the local router:

```text
NLS packet
   |
   v
RSA-PSS verify
   |
   v
RSA-OAEP decrypt
   |
   v
restore original IP packet
   |
   v
NLS TUN -> destination LAN
```

The router never decrypts an IP address with RSA. RSA unwraps the per-packet AES key; AES-GCM then reveals the encrypted original IP packet.

### 3. WAN ingress for an intermediate router

```text
NLS packet
   |
   v
Read visible destination only
   |
   v
Is forwarding path cached?
   |                  |
  yes                no
   |                  |
   |             Router-CA resolves
   |             destination router
   |                  |
   |             Linux/FRR FIB lookup
   |                  |
   |             identify OSPF next hop
   |                  |
   |             resolve next hop as
   |             an NLS router
   +---------+--------+
             |
             v
       forward protected
       packet unchanged
```

Intermediate routers do not decrypt the protected IP packet.

OSPF is not used as an on-demand per-packet request mechanism. OSPF floods link-state information, maintains the LSDB, performs SPF, and FRR/zebra installs the selected route into the Linux FIB. NlsxNetOS reads that current FIB to determine the forwarding next hop.

A next hop that is not registered as an NLS router is rejected for protected forwarding rather than silently bypassing the NLS hop.