# NLS OSPFv2 Registry Synchronization

This is an optional experimental control-plane service. It is disabled by default
and must not be enabled until FRRouting OSPFv2 and the local Router-CA identity
are configured and healthy.

## What it does

- Exports only authenticated local vIP bindings from the NLS registry.
- Signs canonical registry records with the local Ed25519 identity.
- Carries records in area-scoped OSPFv2 opaque LSAs using FRR's local OSPF API.
- Verifies peer records against the current Router-CA directory, ACTIVE status,
  certificate validity, revocation state, and the advertised identity public key.
- Persists a per-vIP sequence/tombstone ledger so stale records cannot resurrect
  a withdrawn binding or reassign a vIP to another router/session.
- Never installs kernel routes from an LSA. FRR routing configuration remains
  operator-controlled.

## Enablement

1. Confirm the router is enrolled and the Router-CA directory/heartbeat is fresh.
2. Confirm FRR OSPFv2 is configured and the command below reports the intended
   router ID: sudo vtysh -c 'show ip ospf'.
3. Edit /etc/default/nlsxnetos-ospf-sync and set NLS_OSPF_SYNC_ENABLED=1.
   Set NLS_OSPF_AREA_ID to the area that should carry NLS metadata. The default
   API endpoint is loopback TCP 2607 and opaque type 250.
4. Enable and start the optional worker:

       sudo systemctl enable --now nls-ospf-sync.service
       sudo systemctl status nls-ospf-sync.service
       sudo journalctl -u nls-ospf-sync.service -f

The worker fails closed if the Router-CA cache is stale, the local key does not
match the active RDR, an incoming record is invalid, or the vIP/sequence policy
rejects an update.

## Disablement

Set NLS_OSPF_SYNC_ENABLED=0, then run:

       sudo systemctl disable --now nls-ospf-sync.service

Do not flush an NLS opaque LSA to signal a withdrawal. The service originates a
signed WITHDRAWN record first; unsigned FRR LSA flush notifications are not trusted
as authorization.

## Scope

The adapter and real two-router FRR interoperability test cover OSPFv2 area
opaque LSAs. This does not establish OSPFv3, BGP, or RIP interoperability. Those
require separate protocol-specific adapters and acceptance tests. End-to-end
production deployment remains experimental until the live daemon/registry
lifecycle, failure recovery, and multi-router interoperability gates pass.
