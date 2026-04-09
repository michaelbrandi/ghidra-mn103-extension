#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}"
export GHIDRA_INSTALL_DIR
ANALYZE="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
SCRIPT_DIR="${TOOLS_DIR}/ghidra_scripts"
INSTALL_USER_EXT="${TOOLS_DIR}/install_mn103_user_extension.sh"

OUT_DIR="${1:-${WS_DIR}/tmp_mn103_headless/abi_golden}"
DEMO_DIR="${OUT_DIR}/demo"
PROJECTS_DIR="${OUT_DIR}/projects"
LOG="${OUT_DIR}/logs/abi_golden.log"
REPORT="${OUT_DIR}/abi_golden_report.txt"

if [[ ! -x "${ANALYZE}" ]]; then
  echo "error: analyzeHeadless not found at ${ANALYZE}" >&2
  exit 1
fi

"${INSTALL_USER_EXT}" "${GHIDRA_INSTALL_DIR}" "${GHIDRA_USER_HOME:-${HOME}}"

mkdir -p "${OUT_DIR}/logs" "${PROJECTS_DIR}"

rm -rf "${DEMO_DIR}"
mkdir -p "${DEMO_DIR}"

python3 "${TOOLS_DIR}/make_mn103_abi_demo.py" \
  --out-dir "${DEMO_DIR}"
sync

PROJECT_NAME="mn103_abi_demo"
rm -rf "${PROJECTS_DIR}/${PROJECT_NAME}.gpr" "${PROJECTS_DIR}/${PROJECT_NAME}.rep"

if ! "${ANALYZE}" "${PROJECTS_DIR}" "${PROJECT_NAME}" \
    -import "${DEMO_DIR}/mn103_abi_demo.elf" \
    -processor "mn10300:LE:32:default" \
    -overwrite \
    -analysisTimeoutPerFile 180 \
    -postScript "AssertAbiModel.java" "${DEMO_DIR}/mn103_abi_demo.manifest.txt" \
    -scriptPath "${SCRIPT_DIR}" \
    > "${LOG}" 2>&1; then
  echo "error: headless analysis failed for ABI demo" >&2
  tail -n 120 "${LOG}" >&2 || true
  exit 1
fi

if ! grep -Fq "ABI_ASSERTION_OK" "${LOG}"; then
  echo "error: ABI assertions did not report success" >&2
  tail -n 120 "${LOG}" >&2 || true
  exit 1
fi

{
  echo "MN103 ABI Golden Report"
  echo "======================="
  echo
  echo "Date: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Ghidra: ${GHIDRA_INSTALL_DIR}"
  echo "Demo: ${DEMO_DIR}/mn103_abi_demo.elf"
  echo
  echo "Manifest: ${DEMO_DIR}/mn103_abi_demo.manifest.txt"
  echo "Log: ${LOG}"
  echo
  echo "Assertion marker:"
  grep -F "ABI_ASSERTION_OK" "${LOG}" | head -n 1
} > "${REPORT}"

echo "Wrote: ${REPORT}"
echo "Wrote: ${LOG}"
