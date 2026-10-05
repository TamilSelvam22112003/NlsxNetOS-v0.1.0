#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
[[ "$EUID" -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || { echo "ERROR: Ubuntu is required." >&2; exit 1; }
case "${VERSION_ID:-}" in
  20.04|22.04|24.04) ;;
  *) echo "ERROR: Supported Ubuntu releases: 20.04, 22.04, 24.04." >&2; exit 1 ;;
esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y frr frr-pythontools iproute2 iputils-ping traceroute ethtool tcpdump nftables conntrack python3 python3-venv python3-pip python3-yaml python3-cryptography python3-scapy openssh-server ca-certificates curl chrony dpkg-dev
DEB_PATH="$ROOT_DIR/nlsxnetos_0.1.0_all.deb"
rm -f "$DEB_PATH"
dpkg-deb --build packaging/deb "$DEB_PATH"
if dpkg-deb -c "$DEB_PATH" | grep -Eq "/etc/frr/(daemons|vtysh\.conf)$"; then
  echo "ERROR: NlsxNetOS package contains FRR-owned files." >&2
  exit 1
fi
apt-get install -y "$DEB_PATH"
dpkg --audit
