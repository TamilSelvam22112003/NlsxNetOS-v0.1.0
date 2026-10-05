#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
systemctl enable --now frr
systemctl enable --now nls-router.service
/usr/bin/nlsxnetos status