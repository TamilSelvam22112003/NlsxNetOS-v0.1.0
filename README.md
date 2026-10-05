# NlsxNetOS

NlsxNetOS is a Python-based network operating system toolkit for Ubuntu and Debian.

It integrates Linux networking and FRRouting with an experimental NLS router security/transport layer and Router-CA trust metadata.

## IOS-like configuration CLI

NlsxNetOS provides its own configuration CLI. It intentionally does **not** replace or modify FRRouting's `vtysh` binary.

After installation on a supported Ubuntu system:

```bash
sudo nlsxnetos
```

You can configure interfaces, NLS LAN/WAN roles, and Router-CA entries:

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

NlsxNetOS(config)# router-ca
NlsxNetOS(config-router-ca)# router-ca 1 2409:4000::/22 jio
NlsxNetOS(config-router-ca)# router-ca 2 2401:4900::/32 airtel
NlsxNetOS(config-router-ca)# exit

NlsxNetOS(config)# end
NlsxNetOS# write memory
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
