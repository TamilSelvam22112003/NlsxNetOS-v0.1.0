#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }
systemctl disable --now nls-router.service || true
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0