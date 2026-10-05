#!/usr/bin/env bash
set -euo pipefail
/usr/bin/nlsxnetos doctor
ip -br address
ip route
ip -6 route
systemctl --no-pager --full status frr || true