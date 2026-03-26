#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}"
GRADLEW="${GHIDRA_INSTALL_DIR}/support/gradle/gradlew"

regen_spec=0
if [[ "${1:-}" == "--regen-spec" ]]; then
  regen_spec=1
  shift
fi

if [[ ! -x "${GRADLEW}" ]]; then
  echo "error: bundled Gradle wrapper not found at ${GRADLEW}" >&2
  exit 1
fi

if [[ "${regen_spec}" -eq 1 ]]; then
  OPC_SOURCE="${WS_DIR}/tmp_mn103/m10300-opc.c"
  if [[ ! -f "${OPC_SOURCE}" ]]; then
    echo "error: missing binutils opcode source: ${OPC_SOURCE}" >&2
    exit 1
  fi

  python3 "${TOOLS_DIR}/gen_mn103_slaspec.py" \
    --opc-source "${OPC_SOURCE}" \
    --out "${EXT_DIR}/data/languages/mn103.slaspec"
fi

cd "${EXT_DIR}"
"${GRADLEW}" buildExtension

LATEST_ZIP="$(ls -1t dist/ghidra_*_ghidra-mn103.zip 2>/dev/null | head -n 1 || true)"
if [[ -n "${LATEST_ZIP}" ]]; then
  echo "Built: ${LATEST_ZIP}"
else
  echo "Built extension zip in dist/."
fi
