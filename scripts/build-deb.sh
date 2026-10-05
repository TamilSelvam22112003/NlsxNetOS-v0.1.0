#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
command -v dpkg-deb >/dev/null
rm -rf packaging/deb/usr packaging/deb/lib packaging/deb/etc
mkdir -p packaging/deb/usr/lib/python3/dist-packages/nlsxnetos packaging/deb/usr/bin packaging/deb/usr/share/doc/nlsxnetos packaging/deb/etc/nlsxnetos packaging/deb/lib/systemd/system
cp -a nlsxnetos/. packaging/deb/usr/lib/python3/dist-packages/nlsxnetos/
install -m 0755 scripts/nlsxnetos-wrapper packaging/deb/usr/bin/nlsxnetos
install -m 0644 config/default.yaml packaging/deb/etc/nlsxnetos/nlsxnetos.yaml
install -m 0644 config/router.yaml packaging/deb/etc/nlsxnetos/router.yaml
install -m 0644 config/nls.yaml packaging/deb/etc/nlsxnetos/nls.yaml
install -m 0644 config/router-ca.yaml packaging/deb/etc/nlsxnetos/router-ca.yaml
install -m 0644 systemd/nlsxnetos.service packaging/deb/lib/systemd/system/nlsxnetos.service
install -m 0644 systemd/nls-router.service packaging/deb/lib/systemd/system/nls-router.service
install -m 0644 systemd/nls-ca.service packaging/deb/lib/systemd/system/nls-ca.service
install -m 0644 README.md packaging/deb/usr/share/doc/nlsxnetos/README.md
rm -rf dist && mkdir dist
dpkg-deb --build packaging/deb dist/nlsxnetos_0.1.0_all.deb
if dpkg-deb --contents dist/nlsxnetos_0.1.0_all.deb | grep -Eq '/etc/frr/|/usr/lib/frr/|/usr/bin/vtysh|/usr/sbin/(zebra|ospfd|ospf6d|bgpd)'; then exit 1; fi