# Ubuntu Router Runtime

NlsxNetOS can turn a supported Ubuntu 22.04 machine into a persistent Linux router without replacing FRRouting.

## Activation

```bash
sudo ./install.sh
sudo nlsxnetos router enable
sudo nlsxnetos router status
```

`router enable` enables IPv4/IPv6 kernel forwarding, enables the installed FRR service, and persists router mode.

## Interface configuration

Use the NlsxNetOS CLI:

```text
NlsxNetOS# configure terminal
NlsxNetOS(config)# interface enp0s3
NlsxNetOS(config-if)# ip address 2001:db8:1::1/64
NlsxNetOS(config-if)# nls role wan
NlsxNetOS(config-if)# no shutdown
NlsxNetOS(config-if)# exit
NlsxNetOS(config)# end
NlsxNetOS# write memory
```

Interface addresses and link state are applied immediately and stored in `/etc/nlsxnetos/router.yaml`. The `nlsxnetos-router.service` unit reapplies the saved configuration after reboot.

## Router-CA registration metadata

After the router has been configured, the operator can record its Router-CA registration metadata:

```bash
sudo nlsxnetos router-ca 1 2409:4000::/22 jio
```

or from configuration mode:

```text
NlsxNetOS(config)# router-ca
NlsxNetOS(config-router-ca)# router-ca 1 2409:4000::/22 jio
```

Today this is local metadata. A future Router-CA service/repository will provide global registration, certificate issuance, lookup, cross-verification and security-event reporting.

## NLS boundary

NLS is not an OSPF/BGP replacement. Linux/FRR remains responsible for ordinary IP routing. NLS is being developed as the secure communication layer between two globally reachable NLS routers.

Current repository functionality includes the cryptographic NLS handshake and authenticated encrypted transport. The future Router-CA protocol will add dynamic destination discovery, certificate exchange/validation, temporary network identity, bilateral Router-CA verification and mismatch reporting.

## Safety

Use documentation-only `2001:db8::/32` addresses only in labs. For real networks, use addresses actually assigned to the interfaces. Do not enable forwarding on a production machine until the LAN/WAN topology and firewall policy are understood.