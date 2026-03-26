#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}"
ANALYZE="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
SCRIPT_DIR="${TOOLS_DIR}/ghidra_scripts"

SAMPLES_DIR="${1:-${WS_DIR}/tmp_fz_extract}"
OUT_DIR="${2:-${WS_DIR}/tmp_mn103_headless/firmware_profile}"
TOP_N="${TOP_N:-20}"
TIMEOUT="${TIMEOUT:-180}"

if [[ ! -x "${ANALYZE}" ]]; then
  echo "error: analyzeHeadless not found at ${ANALYZE}" >&2
  exit 1
fi

if [[ ! -d "${SAMPLES_DIR}" ]]; then
  echo "error: input directory not found: ${SAMPLES_DIR}" >&2
  exit 1
fi

FILES=()
while IFS= read -r f; do
  FILES+=("${f}")
done < <(find "${SAMPLES_DIR}" -maxdepth 1 -type f \( -iname '*.elf' -o -iname '*.bin' \) | sort)
if [[ "${#FILES[@]}" -eq 0 ]]; then
  echo "error: no .elf/.bin files found in ${SAMPLES_DIR}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}/logs" "${OUT_DIR}/projects"
: > "${OUT_DIR}/unknown_summaries.txt"
: > "${OUT_DIR}/unknown_top_per_file.txt"
: > "${OUT_DIR}/failed_files.txt"

for f in "${FILES[@]}"; do
  base="$(basename "${f}")"
  safe_base="$(echo "${base}" | tr -c 'A-Za-z0-9._-' '_')"
  project_name="reg_${safe_base}"
  log="${OUT_DIR}/logs/${safe_base}.log"

  rm -rf "${OUT_DIR}/projects/${project_name}.gpr" "${OUT_DIR}/projects/${project_name}.rep"

  if ! "${ANALYZE}" "${OUT_DIR}/projects" "${project_name}" \
      -import "${f}" \
      -processor "mn10300:LE:32:default" \
      -overwrite \
      -analysisTimeoutPerFile "${TIMEOUT}" \
      -postScript "${SCRIPT_DIR}/ReportUnknownOps.java" "${TOP_N}" "profile" \
      -scriptPath "${SCRIPT_DIR}" \
      > "${log}" 2>&1; then
    echo "${f}" >> "${OUT_DIR}/failed_files.txt"
    continue
  fi

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
    if (byte != "") sum[byte] += cnt;
  }
  END {
    for (b in sum) printf "%s %d\n", b, sum[b];
  }
' "${OUT_DIR}/unknown_top_per_file.txt" | sort -k2,2nr -k1,1 > "${OUT_DIR}/unknown_top_aggregate.txt"

REPORT="${OUT_DIR}/firmware_profile_report.txt"
{
  echo "MN103 Firmware Profile Report"
  echo "============================="
  echo
  echo "Date: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "Ghidra: ${GHIDRA_INSTALL_DIR}"
  echo "Input directory: ${SAMPLES_DIR}"
  echo "Files considered: ${#FILES[@]}"
  echo
  echo "Per-file unknown summary:"
  cat "${OUT_DIR}/unknown_summaries.txt"
  echo
  echo "Aggregate unknown opcode bytes (from per-file top ${TOP_N}):"
  nl -w2 -s'. ' <(head -n "${TOP_N}" "${OUT_DIR}/unknown_top_aggregate.txt")
  echo
  echo "Failed files:"
  if [[ -s "${OUT_DIR}/failed_files.txt" ]]; then
    cat "${OUT_DIR}/failed_files.txt"
  else
    echo "  (none)"
  fi
  echo
  echo "Raw outputs:"
  echo "  - ${OUT_DIR}/unknown_summaries.txt"
  echo "  - ${OUT_DIR}/unknown_top_per_file.txt"
  echo "  - ${OUT_DIR}/unknown_top_aggregate.txt"
  echo "  - ${OUT_DIR}/failed_files.txt"
  echo "  - ${OUT_DIR}/logs/"
} > "${REPORT}"

echo "Wrote: ${REPORT}"
echo "Wrote: ${OUT_DIR}/unknown_summaries.txt"
echo "Wrote: ${OUT_DIR}/unknown_top_per_file.txt"
echo "Wrote: ${OUT_DIR}/unknown_top_aggregate.txt"
echo "Wrote: ${OUT_DIR}/failed_files.txt"
