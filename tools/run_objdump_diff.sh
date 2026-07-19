#!/usr/bin/env bash
#
# Differential disassembly validation against the reference implementation.
#
# The MN103 SLEIGH spec was derived from the GNU binutils opcode tables, so
# binutils' own `mn10300-elf-objdump` is the natural ground truth. This script
# disassembles each input blob with both objdump and headless Ghidra over the
# identical raw byte stream, aligns them by address, and reports measured
# agreement rates (instruction boundary, mnemonic, and mnemonic+operand) plus a
# per-file mismatch list.
#
# A clean corpus decode ratio only shows the decoder accepts the bytes; this is
# the check that shows Ghidra decodes them to the SAME instructions the
# reference does.
#
# Requirements:
#   GHIDRA_INSTALL_DIR   Ghidra 12.0.4 install (default ~/Applications/...)
#   OBJDUMP              path to an mn10300 objdump (build from binutils with
#                        --target=mn10300-elf), or on PATH as mn10300-elf-objdump
#
# Usage:
#   ./tools/run_objdump_diff.sh <corpus_dir> [out_dir]
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}"
ANALYZE="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
OBJDUMP="${OBJDUMP:-mn10300-elf-objdump}"

CORPUS_DIR="${1:-${WS_DIR}/tmp_mn103_public_nvidia_samples}"
OUT_DIR="${2:-${WS_DIR}/tmp_mn103_headless/objdump_diff}"

if ! command -v "${OBJDUMP}" >/dev/null 2>&1 && [[ ! -x "${OBJDUMP}" ]]; then
  echo "error: objdump not found: ${OBJDUMP} (set OBJDUMP to an mn10300 objdump)" >&2
  exit 1
fi
if [[ ! -x "${ANALYZE}" ]]; then
  echo "error: analyzeHeadless not found at ${ANALYZE}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}/logs" "${OUT_DIR}/projects"
"${TOOLS_DIR}/install_mn103_user_extension.sh" "${GHIDRA_INSTALL_DIR}" "${GHIDRA_USER_HOME:-${HOME}}" >/dev/null 2>&1 || true

REPORT="${OUT_DIR}/objdump_diff_report.txt"
: > "${REPORT}"

tot_common=0; tot_len=0; tot_mn=0; tot_full=0
for blob in "${CORPUS_DIR}"/*.bin; do
  [[ -e "${blob}" ]] || continue
  base="$(basename "${blob}")"
  safe="$(echo "${base}" | tr -c 'A-Za-z0-9._-' '_')"

  "${OBJDUMP}" -b binary -m mn10300 -D "${blob}" > "${OUT_DIR}/${safe}.objdump.txt" 2>/dev/null

  rm -rf "${OUT_DIR}/projects/${safe}"
  mkdir -p "${OUT_DIR}/projects/${safe}"
  "${ANALYZE}" "${OUT_DIR}/projects/${safe}" diff \
    -import "${blob}" -processor "mn10300:LE:32:default" -noanalysis \
    -scriptPath "${TOOLS_DIR}/ghidra_scripts" \
    -postScript MN103DumpDisasm.java 0x0 \
    > "${OUT_DIR}/logs/${safe}.log" 2>&1
  grep -oE 'D\|[0-9a-f]+\|[0-9a-f]+\|.*$' "${OUT_DIR}/logs/${safe}.log" \
    | sed 's/[[:space:]]*(GhidraScript).*$//' > "${OUT_DIR}/${safe}.ghidra.txt"

  echo "### ${base}" >> "${REPORT}"
  python3 "${TOOLS_DIR}/mn103_objdump_diff.py" \
    "${OUT_DIR}/${safe}.ghidra.txt" "${OUT_DIR}/${safe}.objdump.txt" \
    "${OUT_DIR}/${safe}.mismatches.txt" | tee -a "${REPORT}" \
    | sed -n 's/^\(same instruction length\|mnemonic agreement\|full (mnemonic+operand\).*/  &/p'
  echo >> "${REPORT}"
done

echo "Report: ${REPORT}"
