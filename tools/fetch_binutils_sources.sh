#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/../tmp_mn103}"
mkdir -p "$OUT_DIR"

fetch_one() {
  local url="$1"
  local out="$2"
  local b64="$out.b64"
  curl -L "$url" -o "$b64"
  if base64 -D -i "$b64" -o "$out" 2>/dev/null; then
    :
  else
    base64 --decode "$b64" > "$out"
  fi
}

fetch_one "https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/opcodes/m10300-opc.c?format=TEXT" "$OUT_DIR/m10300-opc.c"
fetch_one "https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/opcodes/m10300-dis.c?format=TEXT" "$OUT_DIR/m10300-dis.c"
fetch_one "https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/include/opcode/mn10300.h?format=TEXT" "$OUT_DIR/mn10300.h"

echo "Fetched files into: $OUT_DIR"
