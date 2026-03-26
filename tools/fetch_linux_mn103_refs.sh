#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/../tmp_mn103_linux416}"
CACHE_DIR="$ROOT_DIR/../tmp_mn103_cache"
TARBALL="$CACHE_DIR/linux-4.16.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.16.tar.xz"

mkdir -p "$CACHE_DIR"

if [[ ! -f "$TARBALL" ]]; then
  echo "Downloading Linux 4.16 source tarball..."
  curl -L "$KERNEL_URL" -o "$TARBALL"
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Compact extraction for reverse-engineering reference:
# keep only arch/mn10300 plus basic provenance files.
tar -xJf "$TARBALL" \
  -C "$OUT_DIR" \
  --strip-components=1 \
  linux-4.16/arch/mn10300 \
  linux-4.16/MAINTAINERS \
  linux-4.16/COPYING

cat > "$OUT_DIR/README.compact.txt" <<EOF
Compact Linux MN10300 reference tree
====================================

Source tarball:
  $KERNEL_URL

Kernel release:
  Linux 4.16 (last release series that still includes arch/mn10300)

Extracted content:
  - arch/mn10300
  - MAINTAINERS
  - COPYING

This compact tree is intended for disassembly/reverse-engineering reference,
not for kernel build output.
EOF

echo "Fetched compact Linux MN10300 refs into: $OUT_DIR"
