#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}"
export GHIDRA_INSTALL_DIR
SLEIGH="${GHIDRA_INSTALL_DIR}/support/sleigh"
OPC_SOURCE="${OPC_SOURCE:-${WS_DIR}/tmp_mn103/m10300-opc.c}"

OUT_DIR="${1:-${WS_DIR}/tmp_mn103_headless/generator_reconciliation}"
LOG_DIR="${OUT_DIR}/logs"
GEN_SPEC="${OUT_DIR}/mn103.generated.slaspec"
GEN_SLA="${OUT_DIR}/mn103.generated.sla"
REL_SPEC="${OUT_DIR}/mn103.release.slaspec"
REL_SLA="${OUT_DIR}/mn103.release.sla"
GEN_LOG="${LOG_DIR}/generator.log"
SLEIGH_LOG="${LOG_DIR}/sleigh.log"
REL_SLEIGH_LOG="${LOG_DIR}/release_sleigh.log"
DIFF_FILE="${OUT_DIR}/generator_vs_checkedin.diff"
REPORT="${OUT_DIR}/generator_reconciliation_report.txt"
CHECKED_IN_SPEC="${EXT_DIR}/data/languages/mn103.slaspec"

mkdir -p "${LOG_DIR}"

if [[ ! -f "${OPC_SOURCE}" ]]; then
  echo "error: opcode source not found at ${OPC_SOURCE}" >&2
  exit 1
fi

if [[ ! -x "${SLEIGH}" ]]; then
  echo "error: sleigh not found at ${SLEIGH}" >&2
  exit 1
fi

python3 "${TOOLS_DIR}/gen_mn103_slaspec.py" \
  --opc-source "${OPC_SOURCE}" \
  --out "${GEN_SPEC}" \
  > "${GEN_LOG}" 2>&1

compile_status="ok"
if ! "${SLEIGH}" "${GEN_SPEC}" "${GEN_SLA}" > "${SLEIGH_LOG}" 2>&1; then
  compile_status="failed"
fi

cp "${CHECKED_IN_SPEC}" "${REL_SPEC}"
release_status="ok"
if ! "${SLEIGH}" "${REL_SPEC}" "${REL_SLA}" > "${REL_SLEIGH_LOG}" 2>&1; then
  release_status="failed"
fi

diff_status="not-run"
if [[ "${compile_status}" == "ok" ]]; then
  if cmp -s "${GEN_SPEC}" "${CHECKED_IN_SPEC}"; then
    diff_status="identical"
    : > "${DIFF_FILE}"
  else
    diff_status="different"
    diff -u "${CHECKED_IN_SPEC}" "${GEN_SPEC}" > "${DIFF_FILE}" || true
  fi
fi

{
  echo "MN103 Generator Reconciliation Report"
  echo "===================================="
  echo
  echo "Date: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Opcode source: ${OPC_SOURCE}"
  echo "Generated spec: ${GEN_SPEC}"
  echo "Release spec: ${REL_SPEC}"
  echo "Checked-in spec: ${CHECKED_IN_SPEC}"
  echo "Compile status: ${compile_status}"
  echo "Release compile status: ${release_status}"
  echo "Diff status: ${diff_status}"
  echo
  echo "Generator log: ${GEN_LOG}"
  echo "Sleigh log: ${SLEIGH_LOG}"
  echo "Release sleigh log: ${REL_SLEIGH_LOG}"
  if [[ -f "${DIFF_FILE}" && -s "${DIFF_FILE}" ]]; then
    echo "Diff file: ${DIFF_FILE}"
  fi
} > "${REPORT}"

echo "Wrote: ${REPORT}"
echo "Wrote: ${GEN_LOG}"
echo "Wrote: ${SLEIGH_LOG}"
echo "Wrote: ${REL_SLEIGH_LOG}"
if [[ -f "${DIFF_FILE}" && -s "${DIFF_FILE}" ]]; then
  echo "Wrote: ${DIFF_FILE}"
fi

if [[ "${release_status}" != "ok" ]]; then
  echo "error: checked-in release spec did not compile cleanly" >&2
  tail -n 120 "${REL_SLEIGH_LOG}" >&2 || true
  exit 1
fi

if [[ "${compile_status}" != "ok" ]]; then
  echo "error: generated spec did not compile cleanly" >&2
  tail -n 120 "${SLEIGH_LOG}" >&2 || true
fi
