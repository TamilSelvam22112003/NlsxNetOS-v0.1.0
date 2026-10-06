# NlsxNetOS

NlsxNetOS is a Python-based network operating system toolkit for Ubuntu and Debian.

It integrates Linux networking and FRRouting with an experimental NLS router security/transport layer and Router-CA trust metadata.

## Cisco 2911-style NlsxNetOS CLI

NlsxNetOS now exposes an IOS-style configuration experience for the Ubuntu router runtime. The CLI deliberately does **not** replace or modify FRRouting's `vtysh`; FRR continues to own its routing-protocol CLI. citeturn0search0

Start the NlsxNetOS CLI with:

```bash
sudo nlsxnetos
```

The intended workflow is:

```text
NlsxNetOS# enable
NlsxNetOS# enable nlsxnetos
NlsxNetOS# configure terminal

NlsxNetOS(config)# interface g0/0
NlsxNetOS(config-if:g0/0)# ip address 2600:1400:d:5a3::3bd4
NlsxNetOS(config-if:g0/0)# nls lan
NlsxNetOS(config-if:g0/0)# no shutdown
NlsxNetOS(config-if:g0/0)# exit

NlsxNetOS(config)# interface g0/1
NlsxNetOS(config-if:g0/1)# ip address 2601:1400:d:5a3::3bd4
NlsxNetOS(config-if:g0/1)# nls wan
NlsxNetOS(config-if:g0/1)# no shutdown
NlsxNetOS(config-if:g0/1)# exit

NlsxNetOS(config)# interface g0/2
NlsxNetOS(config-if:g0/2)# ip address 2602:1400:d:5a3::3bd4
NlsxNetOS(config-if:g0/2)# nls wan
NlsxNetOS(config-if:g0/2)# no shutdown
NlsxNetOS(config-if:g0/2)# exit

NlsxNetOS(config)# interface g0/3
NlsxNetOS(config-if:g0/3)# ip address 2603:1400:d:5a3::3bd4
NlsxNetOS(config-if:g0/3)# nls wan
NlsxNetOS(config-if:g0/3)# no shutdown
NlsxNetOS(config-if:g0/3)# exit

NlsxNetOS(config)# end
NlsxNetOS# write memory
```

### Cisco interface names on Ubuntu

`g0/0`, `g0/1`, `g0/2`, and `g0/3` are NlsxNetOS logical chassis names. On a fresh configuration they map, in deterministic order, to the non-loopback Linux interfaces detected by the system. The selected Linux name is then persisted in `/etc/nlsxnetos/router.yaml`.

For example:

```text
g0/0 -> enp0s3
g0/1 -> enp0s8
g0/2 -> enp0s9
g0/3 -> enp0s10
```

The actual mapping depends on the Ubuntu machine. Always verify with:

```text
NlsxNetOS# show interfaces
NlsxNetOS# show running-config
```

### IP prefix behavior

Cisco IOS normally requires an IPv6 prefix length for a global IPv6 address. NlsxNetOS accepts your shortened form for convenience and uses `/64` for an IPv6 address when no prefix is supplied. For production configurations, explicitly writing `/64` is recommended. citeturn1search1turn1search3

Example:

```text
ip address 2600:1400:d:5a3::3bd4/64
```

### `no shutdown` activates the Linux router

When `no shutdown` is entered:

1. The mapped Linux interface is brought UP.
2. The configured IP address is installed with `ip address add`.
3. IPv4 forwarding is enabled.
4. IPv6 forwarding is enabled.
5. FRR is started/enabled.
6. The interface configuration remains in the running NlsxNetOS configuration.

Linux forwarding is what allows packets received on one interface to be forwarded through the kernel routing table to another interface. citeturn3search1turn3search0

### `write memory`

NlsxNetOS uses a persistent Ubuntu configuration file instead of physical Cisco NVRAM/ROM:

```text
/etc/nlsxnetos/router.yaml
```

Therefore:

```text
NlsxNetOS# write memory
```

means **save the running NlsxNetOS configuration as the persistent startup configuration**. It is not literally writing to ROM. Cisco IOS's `write memory` likewise means saving the running configuration to nonvolatile startup storage. citeturn2search12turn2search3

At boot, `nlsxnetos-router.service` reapplies the saved interface addresses, interface state, and forwarding state.

### Reboot

The CLI accepts:

```text
NlsxNetOS# reboot
```

which requests a normal Linux system reboot.

### Router-CA command

The requested Cisco-style extension is also accepted:

```text
NlsxNetOS# nlsnetos router-ca 1 ip addr 2001:db8:1::1/64
NlsxNetOS# nlsnetos router-ca 2 ip addr 2001:4860:4860::8844
NlsxNetOS# nlsnetos router-ca 3 ip addr 2409:4000::/22
```

These entries are Router-CA **trust/lookup metadata**. A Router-CA address by itself does not provide a cryptographic peer identity or NLS transport endpoint. For an authenticated NLS tunnel, the complete Router-CA registration still needs the destination router endpoint and Ed25519 public key.

### Important networking boundary

The interface configuration above creates real Linux interfaces, addresses, connected routes, and kernel forwarding. It is enough for directly connected IPv4/IPv6 networks to communicate through the Ubuntu router.

For non-directly-connected networks, the router also needs a route learned through FRR (for example OSPF/OSPFv3/BGP) or an explicit static route. NLS Router-CA metadata does not by itself replace the Linux/FRR routing table.

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
sudo ./install.sh --with-gui
```

The GUI profile installs Ubuntu Desktop Minimal and Firefox. On Ubuntu 22.04/24.04, Ubuntu's `firefox` package is a transitional package for the Firefox Snap.

### Automatic NLS activation

NLS is intentionally inactive until a complete Router-CA destination registration is configured. A Router-CA registration contains:

- destination prefix
- destination NLS endpoint
- destination router Ed25519 public key

Example from the NlsxNetOS terminal:

```text
NlsxNetOS# configure terminal
NlsxNetOS(config)# router-ca
NlsxNetOS(config-router-ca)# router-ca 10 2001:db8:200::/48 remote-router [2001:db8:100::10]:4789 <ED25519_PUBLIC_KEY>
NlsxNetOS(config-router-ca)# exit
NlsxNetOS(config)# end
```

After the first complete Router-CA entry is stored, NlsxNetOS automatically enables the NLS TUN data plane and restarts the NLS service. The Router-CA registry is then used as the destination lookup table and the most-specific prefix wins.

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
   | AES-256-GCM NLS encapsulation
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

The current production integration implements the **Router-CA registry and lookup inside each NlsxNetOS router**. It does not invent a remote Internet-wide Router-CA HTTP API. A future externally hosted/global CA service can populate the same signed identity/endpoint registry without changing the NLS data-plane format.

### GUI safety

NlsxNetOS is a router runtime for Ubuntu, not a replacement desktop distribution. The installer does not purge:

- Ubuntu Desktop / GNOME
- NetworkManager
- Firefox or other browsers
- terminal applications
- normal Ubuntu user applications

The router CLI, NLS services, FRR and routing functions run alongside the Ubuntu graphical environment.
