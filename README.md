# NlsxNetOS

NlsxNetOS is a router operating environment for Ubuntu and Debian.

It turns a supported Ubuntu system into a Linux-based routed networking appliance using Linux forwarding, iproute2 and FRRouting, with NLS as an optional configurable security/transport data plane. This repository contains the router only; it does not implement a client, server, or Router-CA server. The Router-CA is an external trust service consumed through the router-side HTTPS client.

## Production installation profile

The installer supports Ubuntu 22.04 and 24.04, preserves operator configuration on upgrades, backs up existing NlsxNetOS state, validates FRRouting/AppArmor/package state, provisions protected cryptographic keys, and leaves NLS disabled until explicitly configured.

```bash
sudo ./install.sh
```

For a maintenance-window installation without starting the base router runtime:

```bash
sudo ./install.sh --no-start
```

The installer does not remove Ubuntu Desktop, NetworkManager, browsers, or normal user applications.

## IOS-like configuration CLI

NlsxNetOS provides its own configuration CLI. It intentionally does **not** replace or modify FRRouting's `vtysh` binary.

After installation on a supported Ubuntu system:

```bash
sudo nlsxnetos
```

You can configure interfaces and NLS router settings:

```text
NlsxNetOS# enable
NlsxNetOS# configure terminal

NlsxNetOS(config)# interface eth0
NlsxNetOS(config-if:eth0)# ip address 2001:db8:1::1/64
NlsxNetOS(config-if:eth0)# nls role lan
NlsxNetOS(config-if:eth0)# no shutdown
NlsxNetOS(config-if:eth0)# exit

NlsxNetOS(config)# interface eth1
NlsxNetOS(config-if:eth1)# ip address 2001:db8:2::1/64
NlsxNetOS(config-if:eth1)# nls role wan
NlsxNetOS(config-if:eth1)# no shutdown
NlsxNetOS(config-if:eth1)# exit

NlsxNetOS(config)# end
NlsxNetOS# nls configure --router-id R1 --advertised-endpoint [2001:db8:2::1]:4789 --ca-server https://router-ca.example
NlsxNetOS# nls enable
```

Configuration changes to interfaces are applied immediately through Linux `ip` commands. `write memory` persists the NlsxNetOS running configuration to `/etc/nlsxnetos/router.yaml`.

Router-CA is external trust infrastructure; this router does not administer the authoritative CA database. NLS remains disabled until explicitly enabled/configured.

### Important

Use `sudo nlsxnetos`, **not `sudo vtysh`**, for this NlsxNetOS CLI. FRRouting's `vtysh` remains the FRR CLI and is intentionally not modified.

## Existing diagnostics

```bash
sudo nlsxnetos doctor
sudo nlsxnetos frr validate
sudo nlsxnetos nls self-test
sudo nlsxnetos nls status
```


## Production router integration

NlsxNetOS keeps Ubuntu as the host operating system. It does **not** remove GNOME, NetworkManager, desktop applications, or browsers.

For an existing Ubuntu Desktop installation, the normal installer preserves the graphical environment. A fresh Ubuntu installation can optionally receive an Ubuntu GUI profile:

```bash
sudo ./install.sh --with-gui
```

The GUI profile installs Ubuntu Desktop Minimal and Firefox. On Ubuntu 22.04/24.04, Ubuntu's `firefox` package is a transitional package for the Firefox Snap.

### External Router-CA integration

When NLS is enabled, the router uses the external Router-CA service for destination-router discovery and trust validation. A Router-CA destination record contains:

- destination prefix
- destination NLS endpoint
- destination router Ed25519 public key
- destination router RSA encryption public key

Configure the router-side CA endpoint:

```text
sudo nlsxnetos nls configure --router-id R1 --advertised-endpoint [2001:db8:2::1]:4789 --ca-server https://router-ca.example
sudo nlsxnetos nls enable
```

The router registers its Ed25519 identity key plus independent RSA encryption and RSA signing public keys with the external Router-CA and queries it for destination-router records. The authoritative Router-CA database is outside this repository.

### Automatic client/server packet path

Once the external Router-CA is configured and NLS is enabled:

```text
Client LAN
   |
   | ordinary IP packet
   v
Linux routing
   |
   | destination prefix -> nls0
   v
NLS TUN
   |
   | External Router-CA destination lookup
   v
Router identity/trust -> NLS session establishment
   |
   | RSA-OAEP encrypts original IP packet directly
   | RSA-PSS authenticates the NLS packet
   v
NLS UDP / WAN
   |
   v
Destination NLS router
   |
   | verify -> decrypt -> nls0
   v
Destination LAN
   |
   v
Server
```

The return path is automatic in the opposite direction. The destination router routes the client's prefix back into NLS while the original server prefix remains connected on the destination LAN.

NlsxNetOS installs only missing NLS prefix routes. Existing connected/static routes are preserved so a destination LAN prefix is not accidentally redirected into the tunnel.


### GUI safety

NlsxNetOS is a router runtime for Ubuntu, not a replacement desktop distribution. The installer does not purge:

- Ubuntu Desktop / GNOME
- NetworkManager
- Firefox or other browsers
- terminal applications
- normal Ubuntu user applications

The router CLI, NLS services, FRR and routing functions run alongside the Ubuntu graphical environment.


## NLS architecture

NLS separates the system into three logical planes:

1. **Routing Plane — WHERE:** OSPF/OSPFv3, topology discovery, LSDB, SPF calculation, route convergence, and FIB/RIB generation.
2. **Trust / Session Plane — WHO + HOW TO TRUST:** Router-CA trust metadata, router identity validation, temporary identity handling, destination-router validation, X25519 key exchange, HKDF session-key derivation, mutual authentication, and NLS session establishment.
3. **NLS Data Plane — WHAT IS TRANSPORTED:** the original client/server IP packet is protected with RSA-only transport. RSA-OAEP/SHA-256 encrypts the packet directly in chunks with the destination router's RSA public key, and RSA-PSS/SHA-256 authenticates the complete NLS header/ciphertext with the sender router's RSA private key. Intermediate NLS routers forward the protected inner packet without decrypting it.

The detailed design is documented in docs/NLS_THREE_PLANE_ARCHITECTURE.md.

### RSA-only data-plane protection

For the current development phase, NLS does **not** use AES keys or a hybrid RSA+AES construction.

```text
Original IP packet
       |
       v
Split into RSA-OAEP/SHA-256 blocks
       |
       +--> encrypt directly with destination RSA public key
       |
       v
NLS header + RSA ciphertext blocks
       |
       +--> RSA-PSS/SHA-256 signature with sender RSA private key
       |
       v
NLS UDP / WAN
```

The destination NLS router verifies the sender's RSA-PSS signature and decrypts the RSA-OAEP ciphertext blocks with its RSA private key. The router's RSA public key is registered in Router-CA as `encryption_public_key`. No AES data key is generated, transported, wrapped, or used in this mode.

Because RSA directly encrypts the packet, the NLS transport has significantly more overhead than a symmetric data plane. The router validates the configured NLS TUN MTU against the WAN MTU and may require a smaller TUN MTU.

Each router generates independent private keys locally: Ed25519 identity at `/var/lib/nlsxnetos/identity/ed25519.key`, RSA encryption at `/var/lib/nlsxnetos/identity/rsa-encryption.pem`, and RSA signing at `/var/lib/nlsxnetos/identity/rsa-signing.pem`. The corresponding public keys must be registered in Router-CA. One RSA key pair is never reused for both encryption and signing.

### Temporary identity note

SHA-256 produces 64 hexadecimal characters. The current experimental 128-hex-character temporary identifier format can be represented as SHA256(input) || SHA256(input). This is 128 hexadecimal characters / 64 bytes of representation, but repeating a SHA-256 value does not increase cryptographic entropy beyond the underlying 256-bit value. It should therefore be treated as an identifier format, not as a 512-bit-security primitive.


## Router-only repository boundary

NlsxNetOS is the router implementation. Router-CA issuance, authoritative router registration, certificate lifecycle, and the Router-CA server API belong in a separate repository. This router contains only the Router-CA client/trust-consumer interface.

## NLS terminal lifecycle

```text
sudo nlsxnetos nls status
sudo nlsxnetos nls configure --router-id R1 --advertised-endpoint [2001:db8:1::1]:4789 --ca-server https://router-ca.example
sudo nlsxnetos nls enable

# Disable without deleting configuration
sudo nlsxnetos nls disable

# Erase NLS configuration only
sudo nlsxnetos nls erase
```

`nls erase` stops the NLS service and resets only `/etc/nlsxnetos/nls.yaml`. It does not erase router interfaces, FRRouting configuration, or long-term router private keys.
