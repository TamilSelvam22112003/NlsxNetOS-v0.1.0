#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo ./scripts/install/install.sh)." >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in ubuntu:22.04|ubuntu:24.04) ;; *) echo "ERROR: NlsxNetOS supports Ubuntu 22.04 and 24.04 only." >&2; exit 1 ;; esac

GUI_PROFILE=0
if [[ "${1:-}" == "--with-gui" ]]; then
  GUI_PROFILE=1
elif [[ -n "${1:-}" ]]; then
  echo "ERROR: unknown option: $1" >&2
  echo "Usage: sudo ./install.sh [--with-gui]" >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y frr frr-pythontools iproute2 nftables python3 python3-yaml python3-cryptography systemd dpkg-dev

# NlsxNetOS never removes Ubuntu Desktop, GNOME, NetworkManager, browsers, or other
# user applications. A GUI profile is explicit so router installs remain suitable for
# Ubuntu Desktop and for minimal/server images.
if (( GUI_PROFILE )); then
  apt-get install -y ubuntu-desktop-minimal firefox
fi

"$ROOT_DIR/scripts/build/deb.sh"
apt-get install -y "$ROOT_DIR/dist/nlsxnetos_0.1.0_all.deb"
dpkg --audit
if command -v apparmor_parser >/dev/null 2>&1 && [[ -f /etc/apparmor.d/usr.bin.nlsxnetos ]]; then
  apparmor_parser -R /etc/apparmor.d/usr.bin.nlsxnetos || true
fi
/usr/bin/nlsxnetos doctor
if command -v apparmor_parser >/dev/null 2>&1 && [[ -f /etc/apparmor.d/usr.bin.nlsxnetos ]]; then
  apparmor_parser -r /etc/apparmor.d/usr.bin.nlsxnetos
fi
