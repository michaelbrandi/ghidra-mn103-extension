#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}"
ANALYZE="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
SCRIPT_DIR="${TOOLS_DIR}/ghidra_scripts"

SAMPLES_DIR="${1:-${WS_DIR}/tmp_mn103_online_samples}"
OUT_DIR="${2:-${WS_DIR}/tmp_mn103_headless/real_blob_regression}"
TOP_N="${TOP_N:-20}"

FILES=(
  "${SAMPLES_DIR}/nvidia_gp10b_gr_fecs_inst.elf"
  "${SAMPLES_DIR}/nvidia_gp107_gr_fecs_inst.elf"
  "${SAMPLES_DIR}/nvidia_tu117_gr_gpccs_inst.elf"
)

if [[ ! -x "${ANALYZE}" ]]; then
  echo "error: analyzeHeadless not found at ${ANALYZE}" >&2
  exit 1
fi

for f in "${FILES[@]}"; do
  if [[ ! -f "${f}" ]]; then
    echo "error: missing sample file: ${f}" >&2
    exit 1
  fi
done

mkdir -p "${OUT_DIR}/logs" "${OUT_DIR}/projects"
: > "${OUT_DIR}/unknown_summaries.txt"
: > "${OUT_DIR}/unknown_top_per_file.txt"

for f in "${FILES[@]}"; do
  base="$(basename "${f}" .elf)"
  project_name="reg_${base}"
  log="${OUT_DIR}/logs/${base}.log"

  rm -rf "${OUT_DIR}/projects/${project_name}.gpr" "${OUT_DIR}/projects/${project_name}.rep"

  "${ANALYZE}" "${OUT_DIR}/projects" "${project_name}" \
    -import "${f}" \
    -processor "mn10300:LE:32:default" \
    -overwrite \
    -analysisTimeoutPerFile 180 \
    -postScript "${SCRIPT_DIR}/ReportUnknownOps.java" "${TOP_N}" "sweep" \
    -scriptPath "${SCRIPT_DIR}" \
    > "${log}" 2>&1

  sed -n 's/.*UNKNOWN_SUMMARY /UNKNOWN_SUMMARY /p' "${log}" | sed 's/[[:space:]]*(GhidraScript).*$//' >> "${OUT_DIR}/unknown_summaries.txt"
  sed -n 's/.*UNKNOWN_TOP /UNKNOWN_TOP /p' "${log}" | sed 's/[[:space:]]*(GhidraScript).*$//' >> "${OUT_DIR}/unknown_top_per_file.txt"
done

awk '
  $1=="UNKNOWN_TOP" {
    byte=""; cnt=0;
    for (i=1; i<=NF; i++) {
      if ($i ~ /^byte=/)  { split($i, a, "="); byte=a[2]; }
      if ($i ~ /^count=/) { split($i, a, "="); cnt=a[2] + 0; }
    }
    if (byte != "") {
      sum[byte] += cnt;
    }
  }
  END {
    for (b in sum) {
      printf "%s %d\n", b, sum[b];
    }
  }
' "${OUT_DIR}/unknown_top_per_file.txt" | sort -k2,2nr -k1,1 > "${OUT_DIR}/unknown_top_aggregate.txt"

REPORT="${OUT_DIR}/real_blob_regression_report.txt"
{
  echo "MN103 Real-Blob Regression Report"
  echo "================================"
  echo
  echo "Date: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Ghidra: ${GHIDRA_INSTALL_DIR}"
  echo "Samples:"
  for f in "${FILES[@]}"; do
    echo "  - ${f}"
  done
  echo
  echo "Per-file unknown summary:"
  cat "${OUT_DIR}/unknown_summaries.txt"
  echo
  echo "Aggregate unknown opcode bytes (from per-file top ${TOP_N}):"
  nl -w2 -s'. ' <(head -n "${TOP_N}" "${OUT_DIR}/unknown_top_aggregate.txt")
  echo
  echo "Raw outputs:"
  echo "  - ${OUT_DIR}/unknown_summaries.txt"
  echo "  - ${OUT_DIR}/unknown_top_per_file.txt"
  echo "  - ${OUT_DIR}/unknown_top_aggregate.txt"
  echo "  - ${OUT_DIR}/logs/"
} > "${REPORT}"

echo "Wrote: ${REPORT}"
echo "Wrote: ${OUT_DIR}/unknown_summaries.txt"
echo "Wrote: ${OUT_DIR}/unknown_top_per_file.txt"
echo "Wrote: ${OUT_DIR}/unknown_top_aggregate.txt"
