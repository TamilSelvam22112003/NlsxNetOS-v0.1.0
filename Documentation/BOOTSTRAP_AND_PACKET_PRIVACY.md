# Router-CA bootstrap and NLS packet privacy

## Required boot workflow

1. **Boot:** the router starts with a pre-provisioned Router-CA IPv6 endpoint, the Router-CA Ed25519 NLS-control identity pin, the CA root certificate, and protected bootstrap/router-specific enrollment credentials. These trust anchors and credentials must be provisioned out-of-band; a router must not trust a key fetched from an unauthenticated network.
2. **Reachability:** the systemd `nls-ca-client.service` starts after `network-online.target`. The client attempts TCP connectivity to the configured endpoint and retries after failure. A successful TCP connect proves reachability only.
3. **Authenticate and enroll:** the client verifies the pinned Router-CA Ed25519 control key during the NLS Control v1 handshake. X25519 and transcript-bound HKDF-SHA-256 derive directional AES-256-GCM record keys. Enrollment credentials and the CSR are sent inside the protected control channel. The CA validates authorization and issues a router identity certificate.
4. **Reconnect and synchronize:** the router reconnects using its issued certificate, validates the CA root and pinned control identity, then synchronizes policy/revocation state over NLS Control v1.
5. **Data plane:** only after a complete trusted destination registration and usable NLS interface/route exist should the NLS TUN data plane be enabled.

## Packet privacy and public-key roles

The routable **outer destination IP must remain visible**. The original IP packet, including its original source IP, original destination IP, transport headers, and payload, is encrypted as a whole using a fresh AES-256-GCM data key. The data key is wrapped using RSA-OAEP-SHA-256 with the **destination NLS router's registered RSA encryption public key**. Only that destination router's matching private key can unwrap the data key and decrypt the original packet.

Do **not** encrypt user payload with the Router-CA's RSA public key unless the CA is intended to be the payload recipient. Data encrypted to the CA can only be decrypted by the CA private key; that would make the CA a mandatory data-plane decryption intermediary and would not provide end-to-end confidentiality between routers. The CA's pinned Ed25519 control key authenticates the NLS control service; it is distinct from the CA signing certificate and each router's RSA data-encryption key.

Conceptual packet:

```text
Visible outer IP destination
+ NLS header (session/sequence/destination routing metadata)
+ RSA-OAEP(destination-router RSA public key, fresh AES-256-GCM data key)
+ AES-256-GCM(original IP packet: source IP + destination IP + L4 headers + payload)
```

The original source IP is not present as a plaintext field in the NLS encapsulation header. Outer source/destination addresses required by the underlay remain observable; NLS does not hide traffic timing, packet sizes, or the outer router addresses.

## Lab acceptance checks

- Verify boot-persistent IP reachability to the configured CA endpoint.
- Verify the TCP port is owned by `nls-router-ca`, not just that a socket accepts connections.
- Run `sudo nlsxnetos router-ca-client status --config /etc/nlsxnetos/router-ca-client.yaml` and inspect the service journal.
- Verify the CA client reports successful enrollment and subsequent certificate-authenticated sync.
- Run NLS encapsulation unit tests proving the original IPv4/IPv6 source and payload are absent from the visible header/ciphertext and that only the destination RSA private key opens the packet.
- Verify a destination registration has an encryption public key, the NLS TUN and routes are active, and actual test traffic crosses the tunnel. Ping and TCP/4790 alone do not prove data-plane encryption.

NLS Control v1 is an experimental custom protocol and requires independent cryptographic review before production deployment.
