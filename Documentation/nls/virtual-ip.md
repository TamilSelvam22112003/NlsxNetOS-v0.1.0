# NLS v1 virtual IP bootstrap

Use configured vip.pool (lab default fd00::/8) to allocate fresh IPv6 /128. Proposed default layout: fd byte + 40 random prefix bits + configured 16-bit subnet + random 64-bit IID; see OPEN_QUESTIONS.md. Reject collisions/exhaustion. Internet-routed vIP must be selected only within the router's own operator-configured routable prefix, never invented public space.

Before M1, assign ADDRESS/128 to WAN with ip -6 addr add ADDRESS/128 dev IFACE nodad. Lifetime 10 seconds; vIP is actual outer source for M1/M3, M2/M4 target it. Switch to real WAN endpoints only after S verifies M4 and endpoints match signed RDRs. Remove S vIP immediately; later packets sourced from retired vIP drop with NLS_VIP_AFTER_SWITCH. Abort, timeout, shutdown and crash recovery remove only NLS-owned addresses, idempotently. vIP is not an inner address and must not create TUN routes.

Only operator-configured nls route PREFIX via ROUTER-ID commands create routes. CA records authorize but never create routes. Current new_init creates only a textual vip and lsdb stores a mapping; no actual address assignment, 10-second TTL, source switch, or removal exists.