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
  python3 - "$b64" "$out" <<'PY'
from __future__ import annotations

import base64
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
data = src.read_bytes()
decoded = base64.b64decode(b"".join(data.split()))
dst.write_bytes(decoded)
PY
}

fetch_one "https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/opcodes/m10300-opc.c?format=TEXT" "$OUT_DIR/m10300-opc.c"
fetch_one "https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/opcodes/m10300-dis.c?format=TEXT" "$OUT_DIR/m10300-dis.c"
fetch_one "https://android.googlesource.com/toolchain/binutils/+/eclair/binutils-2.17/include/opcode/mn10300.h?format=TEXT" "$OUT_DIR/mn10300.h"

echo "Fetched files into: $OUT_DIR"
