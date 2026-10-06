# NLS Router v1

Production-integration NLS router engine for NlsxNetOS v0.1.0.

## End-to-end packet workflow

1. Ubuntu boots normally, including its graphical desktop when installed.
2. NlsxNetOS router runtime restores forwarding/interface configuration.
3. FRR remains available for conventional routing protocols.
4. Router-CA registrations are loaded from the local authoritative trust registry.
5. A complete Router-CA entry (prefix + NLS endpoint + Ed25519 public key) activates the NLS TUN data plane.
6. The Linux routing table sends configured remote destination prefixes to the NLS TUN interface.
7. The NLS daemon performs longest-prefix Router-CA lookup for each TUN packet.
8. The destination router identity and endpoint are checked against Router-CA.
9. Ed25519-signed NLS INIT/RESPONSE messages authenticate the routers.
10. X25519 ephemeral key agreement and HKDF-SHA256 establish directional session keys.
11. The original IP packet is encrypted using AES-256-GCM.
12. The NLS packet is carried over UDP through the configured WAN/transport interface.
13. The destination router verifies the session, replay window, timestamp, identity and AEAD tag.
14. The original IP packet is written to the destination NLS TUN interface.
15. Existing connected/static routes deliver the recovered packet to the destination LAN/server.
16. The return packet follows the same process using the reverse Router-CA prefix and independent directional session key.

## Router-CA registry

The current implementation deliberately does not invent a remote public Internet Router-CA HTTP API. Router-CA is a local authoritative registry containing the information needed for automatic NLS routing:

    entries:
      - id: 10
        prefix: 2001:db8:200::/48
        label: destination-router
        endpoint: "[2001:db8:100::10]:4789"
        public_key: "<Ed25519 public key>"

A future externally hosted/global Router-CA service can populate or synchronize this registry. The NLS wire protocol does not depend on a proprietary remote API.

### Activation rule

Router-CA trust-only entries may exist without activating NLS. NLS automatic routing activates only when at least one entry has both endpoint and a valid 32-byte Ed25519 public key.

### Lookup rule

Destination lookup is longest-prefix match. For example, 2001:db8:200::/48 wins over 2001:db8::/32 when both contain the destination address.

## Automatic TUN routing

The NLS daemon creates nls0, sets its configured MTU, and installs only missing routes for Router-CA destination prefixes:

    Remote prefix -> nls0 -> NLS daemon -> encrypted UDP

If a destination prefix already exists as a connected/static Linux route, it is left untouched. This is required for the destination router: decrypted server traffic must leave nls0 through the server LAN rather than looping back into NLS.

The daemon also records routes it created under /run/nlsxnetos/nls-routes.json and removes those routes when it shuts down cleanly.

## NLS data-plane encapsulation

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

The complete outer header is authenticated as AES-GCM associated data. Therefore changing the visible destination, identity, session ID, sequence, timestamp or nonce causes authentication failure.

## Security properties

- Persistent Ed25519 router identity.
- Signed NLS INIT/RESPONSE handshake.
- Peer public-key verification.
- Router-CA identity and endpoint consistency validation.
- Ephemeral X25519 key agreement.
- Transcript-bound HKDF-SHA256 directional keys.
- AES-256-GCM authenticated encryption.
- Timestamp freshness.
- Bounded replay protection.
- Session binding.
- Destination-prefix longest-prefix routing.
- Automatic TUN route installation for missing remote prefixes.
- Graceful route cleanup on daemon shutdown.
- Optional binding of the NLS UDP socket to a Linux WAN/NLS interface.

## Ubuntu GUI compatibility

NlsxNetOS remains an Ubuntu networking layer. It does not remove or replace the desktop stack. Ubuntu Desktop, GNOME, NetworkManager, browsers and normal user applications remain available.

For minimal/server installations, the installer provides an explicit --with-gui profile. It installs Ubuntu Desktop Minimal and Firefox rather than silently changing the base system.

## Production boundaries

The following are still intentionally outside this version:

- A remote Internet-wide Router-CA service and synchronization protocol.
- Certificate issuance/renewal/revocation infrastructure.
- Automatic discovery of routers that have never been registered.
- Kernel-space/high-performance NLS datapath.
- Multi-path WAN failover and advanced QoS.
- Hardware acceleration for cryptography.

The Python NLS datapath should therefore be treated as a production-integrated reference/experimental datapath until it has completed multi-router performance, fault-injection, interoperability, and security testing on the target hardware.
