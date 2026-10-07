#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root (sudo ./scripts/install.sh)." >&2; exit 1; }

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:22.04|ubuntu:24.04) ;;
  *) echo "ERROR: NlsxNetOS supports Ubuntu 22.04 and 24.04 only." >&2; exit 1 ;;
esac

START_ROUTER=1
GUI_PROFILE=0
PRESERVE_CONFIG=1

usage() {
  cat <<'EOF'
Usage: sudo ./scripts/install.sh [options]

Options:
  --no-start       Install and validate NlsxNetOS but do not start the router runtime.
  --with-gui       Install the optional Ubuntu Desktop Minimal GUI profile.
  --fresh-config   Replace packaged NlsxNetOS configuration with defaults.
  --help            Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-start) START_ROUTER=0 ;;
    --with-gui) GUI_PROFILE=1 ;;
    --fresh-config) PRESERVE_CONFIG=0 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

export DEBIAN_FRONTEND=noninteractive

echo "[1/8] Preflight"
command -v systemctl >/dev/null
command -v apt-get >/dev/null
command -v dpkg >/dev/null
systemctl is-system-running >/dev/null 2>&1 || true
[[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "aarch64" ]] || {
  echo "ERROR: unsupported CPU architecture: $(uname -m)" >&2; exit 1;
}

echo "[2/8] Backup existing NlsxNetOS state"
BACKUP_ROOT="/var/backups/nlsxnetos"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$BACKUP_ROOT"
if [[ -d /etc/nlsxnetos ]]; then tar -C /etc -czf "$BACKUP_ROOT/etc-nlsxnetos-$STAMP.tgz" nlsxnetos; fi
if [[ -d /var/lib/nlsxnetos ]]; then tar -C /var/lib -czf "$BACKUP_ROOT/var-lib-nlsxnetos-$STAMP.tgz" nlsxnetos; fi

echo "[3/8] Install operating-system dependencies"
apt-get update
apt-get install -y apparmor apparmor-utils frr frr-pythontools iproute2 iputils-ping nftables python3 python3-yaml python3-cryptography systemd dpkg-dev
if (( GUI_PROFILE )); then apt-get install -y ubuntu-desktop-minimal firefox; fi

echo "[4/8] Build and install Debian package"
"$ROOT_DIR/scripts/build-deb.sh"
if (( PRESERVE_CONFIG )); then
  apt-get -o Dpkg::Options::=--force-confold install -y "$ROOT_DIR/dist/nlsxnetos_0.1.0_all.deb"
else
  apt-get -o Dpkg::Options::=--force-confnew install -y "$ROOT_DIR/dist/nlsxnetos_0.1.0_all.deb"
fi

echo "[5/8] Validate package and cryptographic material"
dpkg --audit
/usr/bin/nlsxnetos doctor
/usr/bin/nlsxnetos frr validate
/usr/bin/nlsxnetos router-ca validate
/usr/bin/nlsxnetos nls self-test
/usr/bin/nlsxnetos nls identity >/dev/null
for key in /var/lib/nlsxnetos/identity/ed25519.key /var/lib/nlsxnetos/identity/rsa-encryption.pem /var/lib/nlsxnetos/identity/rsa-signing.pem; do
  [[ -f "$key" ]] || { echo "ERROR: missing protected identity key: $key" >&2; exit 1; }
  [[ "$(stat -c "%U:%G %a" "$key")" == "nlsxnetos:nlsxnetos 600" ]] || { echo "ERROR: insecure key permissions: $key" >&2; exit 1; }
done
[[ "$(stat -c "%U:%G %a" /var/lib/nlsxnetos/identity)" == "nlsxnetos:nlsxnetos 750" ]]
[[ "$(stat -c "%U:%G %a" /etc/nlsxnetos)" == "root:nlsxnetos 750" ]]

echo "[6/8] Load security confinement"
if command -v apparmor_parser >/dev/null 2>&1; then apparmor_parser -r /etc/apparmor.d/usr.bin.nlsxnetos; fi
systemctl daemon-reload

echo "[7/8] Enable production router runtime"
systemctl enable nlsxnetos-router.service >/dev/null
if (( START_ROUTER )); then systemctl start nlsxnetos-router.service; fi
systemctl is-enabled nlsxnetos-router.service >/dev/null
if (( START_ROUTER )); then systemctl is-active nlsxnetos-router.service >/dev/null; fi

echo "[8/8] Final health check"
/usr/bin/nlsxnetos doctor
systemctl --no-pager --full status nlsxnetos-router.service | sed -n "1,12p"

cat <<'EOF'

NlsxNetOS installation completed.

Important:
  * NLS remains disabled until explicitly configured and enabled.
  * The external Router-CA server is NOT part of this router package.
  * Existing NlsxNetOS configuration is preserved by default.
  * Private keys are stored under /var/lib/nlsxnetos/identity with mode 0600.
  * Use: sudo nlsxnetos nls identity
  * Use: sudo nlsxnetos doctor
  * Use: sudo nlsxnetos nls status

For a safe first deployment, configure LAN/WAN interfaces and Router-CA in a
lab/maintenance window before enabling NLS traffic.
EOF
