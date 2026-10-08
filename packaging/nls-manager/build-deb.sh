#!/bin/sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
STAGE="$ROOT/build/nls-manager"
VERSION=0.1.1
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/usr/lib/nls-manager" "$STAGE/usr/lib/python3/dist-packages/nls_manager"
cp "$ROOT/packaging/nls-manager/DEBIAN/control" "$STAGE/DEBIAN/control"
cp "$ROOT/nls-manager/usr/lib/nls-manager/nls-manager-helper" "$STAGE/usr/lib/nls-manager/nls-manager-helper"
cp "$ROOT/nls-manager/usr/bin/nls-manager" "$STAGE/usr/bin/nls-manager"
cp -r "$ROOT/nls-manager/nls_manager/." "$STAGE/usr/lib/python3/dist-packages/nls_manager/"
mkdir -p "$STAGE/usr/share/applications" "$STAGE/usr/share/polkit-1/actions" "$STAGE/usr/share/icons/hicolor/scalable/apps"
cp "$ROOT/nls-manager/usr/share/applications/org.nlsxnetos.NLSManager.desktop" "$STAGE/usr/share/applications/"
cp "$ROOT/nls-manager/usr/share/polkit-1/actions/org.nlsxnetos.NLSManager.policy" "$STAGE/usr/share/polkit-1/actions/"
cp "$ROOT/nls-manager/usr/share/icons/hicolor/scalable/apps/org.nlsxnetos.NLSManager.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/"
chmod 0755 "$STAGE/usr/bin/nls-manager" "$STAGE/usr/lib/nls-manager/nls-manager-helper"
mkdir -p "$ROOT/dist"
dpkg-deb --build --root-owner-group "$STAGE" "$ROOT/dist/nls-manager_"$VERSION"_all.deb"
printf '%s\n' "$ROOT/dist/nls-manager_"$VERSION"_all.deb"
