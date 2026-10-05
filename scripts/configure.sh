#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }
/usr/bin/nlsxnetos status