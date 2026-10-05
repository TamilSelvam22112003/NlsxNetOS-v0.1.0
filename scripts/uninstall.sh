#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }
apt-get purge -y nlsxnetos || true
dpkg --audit
echo "NlsxNetOS removed. FRR was left installed."