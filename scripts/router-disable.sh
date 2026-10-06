#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }
systemctl disable --now nlsxnetos-router.service || true
systemctl disable --now nls-router.service || true
/usr/bin/nlsxnetos router disable
