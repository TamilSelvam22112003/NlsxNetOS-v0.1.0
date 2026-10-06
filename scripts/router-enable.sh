#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }
/usr/bin/nlsxnetos router enable
systemctl enable --now frr
systemctl enable --now nlsxnetos-router.service
/usr/bin/nlsxnetos status
