# NLS VIP and Trust Table Contract

## VIP verification table (temporary)

Each row is scoped to one handshake session and expires within the handshake lifetime. It records the temporary VIP and timestamp, the router identity presented in the peer's signed Router Directory Record (RDR), and the independently verified Router-CA RDR. The identity comparison covers router ID, original IPv6 address, Ed25519 public key (including SPKI DER), RSA encryption public key, certificate DER, WAN endpoints, gateway IPs, prefixes, and certificate serial. Both records must be ACTIVE. Any mismatch or missing record rejects promotion.

The VIP row exposes separate columns: dest_router_ip, dest_router_ip_from_dest_router, dest_router_public_key, dest_router_certificate, symmetric_key_from_dest_router, dest_router_public_key_from_router_ca, dest_router_certificate_from_router_ca, and dest_router_ip_from_router_ca. The symmetric-key column is intentionally null: NLS does not accept a raw symmetric key sent by a peer. NLH2 derives directional session keys using X25519 and HKDF-SHA-256.

## Trust table (authenticated LSDB binding)

Only a completed M1-M4 handshake with valid peer signatures, matching Router-CA records, transcript integrity, and M4 key confirmation may publish authenticated router bindings. Published rows include destination router ID/original IP, public identity key, certificate DER, session ID, expiry, and encryption mode. symmetric_key_available records whether an established session has derived symmetric keys; raw keys remain only in the live session object and are never persisted in the LSDB.

After authenticated SourceToken bindings are committed, the temporary VIP verification row and bootstrap VIP binding are removed/retired. If key establishment or any identity check fails, no trusted binding is published and the handshake aborts. There is no silent asymmetric-only downgrade: if X25519/HKDF or AES-GCM session establishment fails, communication fails closed.
