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

For safety, CA metadata authorizes peer identities and prefixes but never creates routes. Operator routes are configured with `nls route <prefix> via <router-id>` and displayed by `show running-config`; the CLI requires a fresh signed directory, an active non-revoked router record, CA-authorized prefix coverage, and rejects default/local-overlapping/invalid routes. Existing kernel routes are preserved. Prompt 3 gate evidence remains pending exact branch-head CI; NLS itself remains disabled by default until explicitly enabled/configured.

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

The Router-CA operator owns WAN endpoints, gateway IPs, and prefixes. Enrollment requests cannot set these fields. In `trust_mode: ca`, live signed lookups and directory synchronization feed the NLH2 handshake. NLS remains experimental; do not deploy it to production or defence networks until the complete Prompt 4 gate and independent security review pass.

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
   | NLH2 derives directional AES-256-GCM session keys
   | NLE2 authenticates its fixed 32-byte header as AAD
   | Inner IP packet encrypted with sequence-derived nonce
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

The current branch uses the NLH2 M1–M4 handshake and verified Router-CA records. NLE2 is the only active data path. The unsigned YAML trust path is removed. The full lifecycle gate—including rekey, live revocation/freshness teardown, benchmark evidence, and independent review—must pass before production use.

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

### NLE2 session-key data-plane protection

The NLH2 handshake derives independent directional AES-256-GCM keys and 4-byte IV prefixes. NLE2 packets use a fixed 32-byte header as AEAD associated data; it contains the protocol marker/version, reserved flags, session ID, and 64-bit sequence number. It contains no inner source or destination address. The nonce is the directional 4-byte IV prefix concatenated with the 64-bit sequence number. Inner IP headers and payload are encrypted together.

There is no per-packet AES key generation or RSA key wrapping in the active data path. RSA remains available only for the handshake envelope where required by the current suite. The receiver commits replay-window state only after AEAD verification, enforces peer/local RDR prefix policy, and writes authenticated inner packets to the TUN. Rekey, live revocation/freshness teardown, measured throughput, and full route-isolation evidence remain Prompt 4 gate items.

### Temporary identity note

SHA-256 produces 64 hexadecimal characters. The current experimental 128-hex-character temporary identifier format can be represented as SHA256(input) || SHA256(input). This is 128 hexadecimal characters / 64 bytes of representation, but repeating a SHA-256 value does not increase cryptographic entropy beyond the underlying 256-bit value. It should therefore be treated as an identifier format, not as a 512-bit-security primitive.
