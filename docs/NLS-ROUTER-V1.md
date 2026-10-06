# NLS Router v1

Experimental NLS Router engine for NlsxNetOS v0.1.0.

## Security and trust sequence

NLS data encapsulation is available only through an established authenticated NLS session.

The intended sequence is:

1. Determine the destination prefix from the original destination IP.
2. Resolve the destination NLS peer through the configured Router-CA trust metadata.
3. Validate the peer identity/public key against the Router-CA registration.
4. Establish the NLS session with signed Ed25519 handshake messages and ephemeral X25519 key agreement.
5. Derive directional session keys with HKDF-SHA256.
6. Carry original IP traffic through the established NLS data plane.

The current repository does **not** invent or implement an undocumented remote Router-CA HTTP/API protocol. The configured Router-CA store is the local trust cache/registration interface. A future Router-CA repository/service can provide the global lookup layer without changing the NLS data-plane wire format.

## NLS data-plane encapsulation

After trust and session establishment, the original IP packet is encapsulated as:

```
NLS OUTER HEADER
  Original destination IP       visible
  NLS/router source identity    visible
  Session ID                    visible
  Sequence number               visible
  Timestamp                    visible
  Nonce                         visible

ENCRYPTED INNER PACKET
  Original source IP
  Original destination IP
  TCP/UDP/other transport
  Application payload

AEAD authentication tag
```

The original destination IP is deliberately visible in the NLS header so that destination-prefix routing remains possible without decrypting the inner packet. The inner copy of the destination IP remains encrypted so that the recovered original IP packet is unchanged.

The UDP/IP endpoint used to carry the NLS packet is the trusted peer's configured NLS endpoint. Therefore, the visible NLS destination field and the transport endpoint have separate roles:

- **NLS destination field:** original destination IP used for policy/prefix routing.
- **Transport endpoint:** destination NLS router address learned/configured for the trusted peer.
- **Encrypted inner packet:** complete original IP packet, including the source address and payload.

The authenticated encryption covers the complete NLS outer header as AAD. Tampering with the visible destination, session ID, sequence, timestamp, or source identity therefore causes authentication failure.

## Request and reply

Once the NLS session is established, both directions use the same model with independent directional keys:

```
Request:
Client
  -> Local NLS Router
  -> NLS encapsulation + encryption
  -> Secure NLS transport
  -> Destination NLS Router
  -> AEAD verification + decryption
  -> Destination

Reply:
Destination
  -> Destination NLS Router
  -> NLS encapsulation + encryption
  -> Secure NLS transport
  -> Local NLS Router
  -> AEAD verification + decryption
  -> Client
```

The NLS session is established before application data is accepted. Router-CA is not queried for every data packet; the established authenticated session is used until it expires or is rejected.

## Destination-prefix routing

NLS peer configuration supports `allowed_prefixes`. When a packet is read from the NLS TUN interface, the destination IP is extracted and the daemon selects the most-specific trusted peer prefix.

Example:

```yaml
peers:
  - id: destination-router
    endpoint: "[2001:db8:100::10]:4789"
    public_key: "<Ed25519-public-key>"
    router_ca_id: 10
    allowed_prefixes:
      - "2001:db8:200::/48"
```

The prefix mapping does not create Linux routes by itself. Linux/TUN routing remains an explicit deployment configuration.

## Implemented security properties

- Persistent Ed25519 router identity.
- Signed NLS INIT/RESPONSE handshake.
- Peer public-key verification.
- Ephemeral X25519 key agreement.
- Transcript-bound HKDF-SHA256 directional keys.
- AES-256-GCM authenticated encryption.
- Timestamp freshness.
- Bounded replay protection for NLS data packets.
- Session binding.
- Visible destination field authenticated as AEAD associated data.
- Original source IP and inner packet protected by AEAD.
- Local Router-CA consistency checking before session establishment.
- Optional binding of the NLS UDP socket to a Linux WAN/NLS interface.

## Current boundaries

Not implemented in this repository:

- A remote/global Router-CA service or undocumented API.
- Certificate issuance, renewal, or revocation.
- Automatic Router-CA discovery.
- Automatic Linux route installation for NLS prefixes.
- Automatic TUN route installation.
- Automatic rekeying.
- Complete integration of the NLS TUN device with the host's normal IP forwarding path.
- Production-performance kernel datapath.

The Python datapath is experimental and intended for isolated authorized testing.

## Packet path

```
Application / IP packet
        |
        v
Destination prefix lookup
        |
        v
Trusted NLS peer/session
        |
        v
NLS outer header + encrypted inner IP packet
        |
        v
WAN / NLS transport endpoint
        |
        v
Destination NLS router
        |
        v
AEAD verification + replay check
        |
        v
Original IP packet recovered
        |
        v
Destination network
```
