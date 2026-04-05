#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}"
export GHIDRA_INSTALL_DIR
ANALYZE="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
SCRIPT_DIR="${TOOLS_DIR}/ghidra_scripts"

SYMBOLS_ROOT="${1:-${WS_DIR}/tmp_mn103_linux416}"
OUT_DIR="${2:-${WS_DIR}/tmp_mn103_headless/instruction_golden}"
DEMO_DIR="${OUT_DIR}/demo"
PROJECTS_DIR="${OUT_DIR}/projects"
LOG="${OUT_DIR}/logs/instruction_golden.log"
REPORT="${OUT_DIR}/instruction_golden_report.txt"

if [[ ! -x "${ANALYZE}" ]]; then
  echo "error: analyzeHeadless not found at ${ANALYZE}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}/logs" "${PROJECTS_DIR}"

SYMBOLS_DIR="${SYMBOLS_ROOT}/ghidra_symbols"
if [[ ! -f "${SYMBOLS_DIR}/mn103_linux416_syscalls.csv" || ! -f "${SYMBOLS_DIR}/mn103_linux416_exception_vectors.csv" ]]; then
  "${TOOLS_DIR}/fetch_linux_mn103_refs.sh" "${SYMBOLS_ROOT}"
  python3 "${TOOLS_DIR}/extract_linux_mn103_symbols.py" --linux-root "${SYMBOLS_ROOT}"
fi

rm -rf "${DEMO_DIR}"
mkdir -p "${DEMO_DIR}"

python3 "${TOOLS_DIR}/make_mn103_instruction_demo.py" \
  --symbols-dir "${SYMBOLS_DIR}" \
  --out-dir "${DEMO_DIR}"

PROJECT_NAME="mn103_instruction_mix_demo"
rm -rf "${PROJECTS_DIR}/${PROJECT_NAME}.gpr" "${PROJECTS_DIR}/${PROJECT_NAME}.rep"

# Force the ELF loader so headless import stays deterministic on fresh
# settings dirs. The synthetic demo ELF carries the correct machine ID, so the
# loader can still auto-select the MN103 language once imported.
if ! "${ANALYZE}" "${PROJECTS_DIR}" "${PROJECT_NAME}" \
    -import "${DEMO_DIR}/mn103_instruction_mix_demo.elf" \
    -loader "ElfLoader" \
    -overwrite \
    -analysisTimeoutPerFile 180 \
    -postScript "PrintEntryInstructions.java" \
    -scriptPath "${SCRIPT_DIR}" \
    > "${LOG}" 2>&1; then
  echo "error: headless analysis failed for instruction golden demo" >&2
  tail -n 80 "${LOG}" >&2 || true
  exit 1
fi

required_lines=(
  "00002000: mov 0x31,D0"
  "00002002: mov 0x64,A0"
  "00002004: mov 0x1000,D0"
  "00002010: mov (A0),A1"
  "0000201c: fmov R5,FPCR"
  "0000201f: add 0x12340000,D0"
  "00002025: cmp 0xaa0000,D0"
  "0000202d: add 0x22,SP"
  "0000203a: xor 0xf0f,D0"
  "0000203e: bra 0x0000203e"
)

for needle in "${required_lines[@]}"; do
  if ! grep -Fq "${needle}" "${LOG}"; then
    echo "error: missing golden instruction anchor: ${needle}" >&2
    tail -n 80 "${LOG}" >&2 || true
    exit 1
  fi
done

if ! grep -Fq "Printed 19 instructions" "${LOG}"; then
  echo "error: unexpected golden instruction count" >&2
  tail -n 80 "${LOG}" >&2 || true
  exit 1
fi

{
  echo "MN103 Instruction Golden Report"
  echo "==============================="
  echo
  echo "Date: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Ghidra: ${GHIDRA_INSTALL_DIR}"
  echo "Demo: ${DEMO_DIR}/mn103_instruction_mix_demo.elf"
  echo
  echo "Verified anchors:"
  printf '  - %s\n' "${required_lines[@]}"
  echo
  echo "Log: ${LOG}"
} > "${REPORT}"

echo "Wrote: ${REPORT}"
echo "Wrote: ${LOG}"
