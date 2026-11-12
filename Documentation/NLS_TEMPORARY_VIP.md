# Temporary vIP lifecycle (experimental)

1. Each router has a stable cryptographic identity key. On initialization it
   generates a fresh random boot/session nonce and derives a temporary IPv6
   address inside the configured NLS overlay ULA /64 using SHA-256.
2. The Router-CA validates the router identity first, then atomically reserves
   the candidate vIP in its registry with router ID, nonce/session, and expiry.
3. If the address is already reserved, the router generates a new nonce and
   retries. A hash alone cannot guarantee collision-free assignment.
4. The peer's authenticated identity and temporary vIP are bound to the
   authenticated NLS session. Never accept a vIP-to-key binding from an
   unauthenticated packet.
5. On expiry, logout, revocation or session teardown, the CA/peer registry
   invalidates the reservation. A stale vIP must not be reused until expiry and
   replay windows have been handled.

The current helper derives a candidate only. It does not reserve the address,
install routes, create a TUN interface, or integrate with enrollment/packet
forwarding. Use an NLS-only ULA prefix such as `fd42:4e4c:5300:1::/64` only if
it is allocated uniquely for this lab; do not use it as a globally routable IP.
