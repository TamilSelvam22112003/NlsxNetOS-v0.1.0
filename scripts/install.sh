#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo ./install.sh)." >&2; exit 1; }
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in ubuntu:22.04|ubuntu:24.04) ;; *) echo "ERROR: NlsxNetOS supports Ubuntu 22.04 and 24.04 only." >&2; exit 1 ;; esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y frr frr-pythontools iproute2 nftables python3 python3-yaml python3-cryptography systemd dpkg-dev
"$ROOT_DIR/scripts/build-deb.sh"
apt-get install -y "$ROOT_DIR/dist/nlsxnetos_0.1.0_all.deb"
dpkg --audit
/usr/bin/nlsxnetos doctor