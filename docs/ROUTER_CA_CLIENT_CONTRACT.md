# Router-CA Client Contract

NlsxNetOS is the router-side implementation. The authoritative Router-CA server is intentionally outside this repository.

## HTTPS endpoints expected by the router

### Health

GET `/v1/health`

Response:

```json
{"status":"ok"}
```

### Resolve a destination

GET `/v1/routers/resolve?ip=<destination-ip>`

Response:

```json
{
  "router": {
    "id": 10,
    "prefix": "2001:db8:200::/48",
    "label": "destination-router",
    "endpoint": "[2001:db8:20::1]:4789",
    "public_key": "<base64 Ed25519 public key>",
    "encryption_public_key": "<base64 DER SubjectPublicKeyInfo RSA public key>",
    "signing_public_key": "<base64 DER SubjectPublicKeyInfo RSA public key>",
    "certificate": "<CA-issued router certificate>",
    "timestamp": 1791370000
  }
}
```

The router uses the most-specific prefix selected by the CA service.

### Resolve a router by identity key

GET `/v1/routers/resolve-identity?public_key=<base64-ed25519-public-key>`

Response:

```json
{
  "router": {
    "id": 1,
    "prefix": "2001:db8:100::/48",
    "label": "source-router",
    "endpoint": "[2001:db8:10::1]:4789",
    "public_key": "<base64 Ed25519 public key>",
    "encryption_public_key": "<base64 DER SubjectPublicKeyInfo RSA public key>",
    "certificate": "<CA-issued router certificate>",
    "timestamp": 1791370000
  }
}
```

The destination router uses this operation when an NLS INIT presents an identity
that is not already cached locally. The CA response is then used to bind the
initiator identity, endpoint, RSA encryption key, and CA metadata before the
handshake is accepted.

### Resolve an NLS transport next hop

GET `/v1/routers/resolve-next-hop?ip=<next-hop-ip>`

The Router-CA resolves an OSPF/Linux transport next-hop address to the registered
router record. This is distinct from destination-prefix resolution: a next-hop
address belongs to the transport topology, while the destination-prefix lookup
identifies the final NLS termination router.

The response uses the same router-record structure as the other lookup APIs.

### Retrieve a router record

GET `/v1/routers/<id>`

The response uses the same router-record structure.

### Register this router

POST `/v1/routers/register`

Request:

```json
{
  "router_id": "R1",
  "endpoint": "[2001:db8:10::1]:4789",
  "public_key": "<base64 Ed25519 public key>",
  "encryption_public_key": "<base64 DER SubjectPublicKeyInfo RSA public key>",
  "signing_public_key": "<base64 DER SubjectPublicKeyInfo RSA public key>",
  "timestamp": 1791370000
}
```

The CA server should return the authoritative registration record, including the CA-issued certificate and CA timestamp when available.

## Security requirements

The router uses HTTPS with Python's default certificate verification unless an explicit `ca_file` is configured. The Router-CA server must therefore present a certificate trusted by the router. The router does not disable TLS verification.

The Router-CA is authoritative for router identity, endpoint, certificate and public-key association. The NLS handshake additionally proves possession of the corresponding Ed25519 private key and binds the CA certificate/timestamp fields into the signed handshake.

This repository does **not** implement:

- CA private keys
- certificate issuance
- certificate signing
- authoritative registry storage
- certificate revocation authority
- CA HTTP server endpoints

Those belong to the separate Router-CA repository.


### Cryptographic key separation

Every NLS-capable Router-CA registration MUST bind three independent public keys to the same router identity:

- `public_key`: Ed25519 router identity key used by the NLS session handshake.
- `encryption_public_key`: RSA-3072 public key used only for RSA-OAEP/SHA-256 encryption.
- `signing_public_key`: RSA-3072 public key used only for RSA-PSS/SHA-256 packet authentication.

The router MUST reject an incomplete NLS registration. The Router-CA MUST NOT allow one RSA key pair to serve both encryption and signing purposes. This separation is required for the production security profile.
