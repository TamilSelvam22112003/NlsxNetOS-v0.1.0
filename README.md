# NlsxNetOS

NlsxNetOS is a Python-based network operating system toolkit for Ubuntu and Debian.

It integrates Linux networking and FRRouting with an experimental NLS router security/transport layer and Router-CA trust metadata.

## IOS-like configuration CLI

NlsxNetOS provides its own configuration CLI. It intentionally does **not** replace or modify FRRouting's `vtysh` binary.

After installation on a supported Ubuntu system:

```bash
sudo nlsxnetos
```

You can configure interfaces and NLS LAN/WAN roles. Router-CA trust entries are no longer accepted as unsigned YAML; import a signed directory bundle using the command shown below.

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
NlsxNetOS# write memory
```

Import an operator-transferred Router-CA-signed directory bundle from the shell:

```bash
sudo nlsxnetos router-ca import /path/to/router-directory.bundle.json
sudo nlsxnetos router-ca list
```

Configuration changes to interfaces are applied immediately through Linux `ip` commands. `write memory` persists the NlsxNetOS running configuration to `/etc/nlsxnetos/router.yaml`.

For safety, Router-CA entries remain trust metadata; they do not create Linux routes. NLS itself remains disabled by default until explicitly enabled/configured.

### Important

Use `sudo nlsxnetos`, **not `sudo vtysh`**, for this NlsxNetOS CLI. FRRouting's `vtysh` remains the FRR CLI and is intentionally not modified.

## Existing diagnostics

```bash
sudo nlsxnetos doctor
sudo nlsxnetos frr validate
sudo nlsxnetos nls self-test
sudo nlsxnetos nls status
sudo nlsxnetos router-ca list
```


## Production router integration

NlsxNetOS keeps Ubuntu as the host operating system. It does **not** remove GNOME, NetworkManager, desktop applications, or browsers.

For an existing Ubuntu Desktop installation, the normal installer preserves the graphical environment. A fresh Ubuntu installation can optionally receive an Ubuntu GUI profile:

```bash
sudo ./scripts/install/install.sh --with-gui
```

The GUI profile installs Ubuntu Desktop Minimal and Firefox. On Ubuntu 22.04/24.04, Ubuntu's `firefox` package is a transitional package for the Firefox Snap.

### Router-CA directory trust

The router trusts directory records only when they are covered by a canonical-CBOR signature from the out-of-band pinned Router-CA control identity key. Configure the control identity pin in the Router-CA client configuration, then import an operator-exported bundle for offline mode:

```bash
sudo nlsxnetos router-ca import /path/to/router-directory.bundle.json
sudo nlsxnetos router-ca list
sudo nlsxnetos nls status
```

The Router-CA operator owns WAN endpoints, gateway IPs, and prefixes. Enrollment requests cannot set these fields. In `trust_mode: ca`, the client exposes live lookup and directory-sync operations; the legacy data-plane handshake is not yet wired to them in this Prompt 2 revision and is scheduled for Prompt 3. The current NLS runtime remains experimental and must not be treated as production-ready.

### Automatic client/server packet path

Once Router-CA entries exist and the router is enabled:

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
   | Router-CA longest-prefix lookup
   v
Ed25519 trust -> NLS handshake -> X25519/HKDF
   |
   | Generate random AES-256 data key
   | RSA-OAEP wraps AES data key
   | AES-256-GCM protects original IP packet
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

### Router-CA scope

The current branch implements the Router-CA registry and signed directory client API, but the legacy handshake is not yet switched to live CA lookup. The unsigned YAML trust path has been removed. The full handshake and data-plane integration is gated by subsequent prompts; do not use the current branch for production or defence networks.

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
3. **NLS Data Plane — WHAT IS TRANSPORTED:** the original client/server IP packet is protected with AES-256-GCM, including the original source/destination addresses, TCP/UDP information, and application payload. Intermediate NLS routers use the permitted forwarding information without decrypting the protected inner packet.

The detailed design is documented in Documentation/NLS_THREE_PLANE_ARCHITECTURE.md.

### RSA hybrid data-plane protection

NLS uses a hybrid construction for the protected original IP packet:

```text
Original IP packet
       |
       v
Random AES-256 data key
       |
       +--> AES-256-GCM encrypts the original IP packet
       |
       +--> RSA-OAEP (destination public key) protects the AES data key
       |
       v
NLS packet = visible destination metadata + RSA-wrapped AES key + ciphertext + GCM tag
```

The destination NLS router uses its RSA private key to unwrap the per-packet AES key and then authenticates/decrypts the inner IP packet. Intermediate routers do not need the RSA private key to forward the NLS transport packet. RSA is not used to encrypt the full IP packet directly.

Each router generates its RSA encryption private key locally at `/var/lib/nlsxnetos/identity/rsa-encryption.pem`. The corresponding public key must be registered in Router-CA as `encryption_public_key`.

### Temporary identity note

SHA-256 produces 64 hexadecimal characters. The current experimental 128-hex-character temporary identifier format can be represented as SHA256(input) || SHA256(input). This is 128 hexadecimal characters / 64 bytes of representation, but repeating a SHA-256 value does not increase cryptographic entropy beyond the underlying 256-bit value. It should therefore be treated as an identifier format, not as a 512-bit-security primitive.
