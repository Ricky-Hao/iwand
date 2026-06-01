#!/usr/bin/env bash
# Convert a .deb package to an OpenWrt .ipk with the specified architecture.
# Usage: deb2ipk.sh <architecture> <input.deb> <output.ipk>

set -euo pipefail

ARCH="$1"
DEB_FILE="$2"
OUT_FILE="$3"

TMP_DIR=$(mktemp -d)
trap "rm -rf '$TMP_DIR'" EXIT

cp "$DEB_FILE" "$TMP_DIR/"
pushd "$TMP_DIR" > /dev/null

ar x "$(basename "$DEB_FILE")"

mkdir control
pushd control > /dev/null
tar xzf ../control.tar.gz
rm -f md5sums
sed -i "s/Architecture: .*/Architecture: $ARCH/" control
tar czf ../control.tar.gz ./*
popd > /dev/null

# Repack as IPK (gzipped tar, OpenWrt format: debian-binary first, with ./ prefix)
(cd "$TMP_DIR" && tar --format=gnu -czf "package.ipk" ./debian-binary ./data.tar.gz ./control.tar.gz)
popd > /dev/null

cp "$TMP_DIR/package.ipk" "$OUT_FILE"
