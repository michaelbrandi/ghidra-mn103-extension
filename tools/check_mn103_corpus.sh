#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

FIRMWARE_DIR="${1:-${WS_DIR}/tmp_fz_extract}"
REAL_BLOB_DIR="${2:-${WS_DIR}/tmp_mn103_online_samples}"
DEMO_DIR="${3:-${WS_DIR}/tmp_mn103_samples}"
PUBLIC_NVIDIA_DIR="${4:-${WS_DIR}/tmp_mn103_public_nvidia_samples}"
PUBLIC_PANASONIC_DIR="${5:-${WS_DIR}/tmp_mn103_public_panasonic_samples}"
OUT_ROOT="${OUT_ROOT:-${WS_DIR}/tmp_mn103_headless/mn103_gate}"
TIMINGS_FILE="${OUT_ROOT}/performance_metrics.txt"
GATE_REPORT="${OUT_ROOT}/mn103_corpus_gate_report.txt"

check_unknown_zero() {
  local summary_file="$1"
  local label="$2"
  local unknown

  if [[ ! -f "${summary_file}" ]]; then
    echo "error: missing summary file for ${label}: ${summary_file}" >&2
    exit 1
  fi

  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    unknown="${line##*unknown=}"
    unknown="${unknown%% *}"
    if [[ "${unknown}" != "0" ]]; then
      echo "error: ${label} has non-zero unknowns: ${line}" >&2
      exit 1
    fi
  done < "${summary_file}"
}

check_no_failed_files() {
  local failed_file="$1"
  local label="$2"

  if [[ ! -f "${failed_file}" ]]; then
    echo "error: missing failure list for ${label}: ${failed_file}" >&2
    exit 1
  fi

  if [[ -s "${failed_file}" ]]; then
    echo "error: ${label} reported failed files:" >&2
    cat "${failed_file}" >&2
    exit 1
  fi
}

FIRMWARE_OUT="${OUT_ROOT}/firmware_profile"
REAL_BLOB_OUT="${OUT_ROOT}/real_blob_regression"
DEMO_OUT="${OUT_ROOT}/demo_profile"
PUBLIC_NVIDIA_OUT="${OUT_ROOT}/public_nvidia_profile"
PUBLIC_PANASONIC_OUT="${OUT_ROOT}/public_panasonic_profile"

# Always start the validation gate from a clean slate so stale logs or partial
# reports from earlier runs cannot be mistaken for the current result.
rm -rf "${FIRMWARE_OUT}" "${REAL_BLOB_OUT}" "${DEMO_OUT}" "${PUBLIC_NVIDIA_OUT}" "${PUBLIC_PANASONIC_OUT}"
mkdir -p "${OUT_ROOT}"
: > "${TIMINGS_FILE}"
GATE_START="${SECONDS}"

run_stage() {
  local label="$1"
  shift
  local start="${SECONDS}"
  set +e
  "$@"
  local status=$?
  set -e
  local duration=$((SECONDS - start))
  printf '%s duration_seconds=%d status=%d\n' "${label}" "${duration}" "${status}" >> "${TIMINGS_FILE}"
  return "${status}"
}

if ! run_stage "firmware corpus" "${TOOLS_DIR}/run_firmware_profile.sh" "${FIRMWARE_DIR}" "${FIRMWARE_OUT}"; then
  exit 1
fi
if ! run_stage "real blob regression" "${TOOLS_DIR}/run_real_blob_regression.sh" "${REAL_BLOB_DIR}" "${REAL_BLOB_OUT}"; then
  exit 1
fi
if ! run_stage "demo corpus" "${TOOLS_DIR}/run_firmware_profile.sh" "${DEMO_DIR}" "${DEMO_OUT}"; then
  exit 1
fi
if ! run_stage "instruction golden" "${TOOLS_DIR}/run_instruction_golden.sh" "${WS_DIR}/tmp_mn103_linux416" "${OUT_ROOT}/instruction_golden"; then
  exit 1
fi
if ! run_stage "public NVIDIA corpus prep" "${TOOLS_DIR}/fetch_public_nvidia_mn103_samples.sh" "${PUBLIC_NVIDIA_DIR}"; then
  exit 1
fi
if ! run_stage "public NVIDIA profile" "${TOOLS_DIR}/run_firmware_profile.sh" "${PUBLIC_NVIDIA_DIR}" "${PUBLIC_NVIDIA_OUT}"; then
  exit 1
fi
if ! run_stage "public Panasonic gate" "${TOOLS_DIR}/run_public_panasonic_gate_profile.sh" "${PUBLIC_PANASONIC_OUT}" "${PUBLIC_PANASONIC_DIR}"; then
  exit 1
fi

check_unknown_zero "${FIRMWARE_OUT}/unknown_summaries.txt" "firmware corpus"
check_no_failed_files "${FIRMWARE_OUT}/failed_files.txt" "firmware corpus"

check_unknown_zero "${REAL_BLOB_OUT}/unknown_summaries.txt" "real blob regression"

check_unknown_zero "${DEMO_OUT}/unknown_summaries.txt" "demo corpus"
check_no_failed_files "${DEMO_OUT}/failed_files.txt" "demo corpus"

check_unknown_zero "${PUBLIC_NVIDIA_OUT}/unknown_summaries.txt" "public NVIDIA corpus"
check_no_failed_files "${PUBLIC_NVIDIA_OUT}/failed_files.txt" "public NVIDIA corpus"

check_unknown_zero "${PUBLIC_PANASONIC_OUT}/unknown_summaries.txt" "public Panasonic corpus"
check_no_failed_files "${PUBLIC_PANASONIC_OUT}/failed_files.txt" "public Panasonic corpus"

TOTAL_DURATION=$((SECONDS - GATE_START))

{
  echo "MN103 corpus validation passed."
  echo "  firmware: ${FIRMWARE_OUT}/firmware_profile_report.txt"
  echo "  real blobs: ${REAL_BLOB_OUT}/real_blob_regression_report.txt"
  echo "  demos: ${DEMO_OUT}/firmware_profile_report.txt"
  echo "  instruction golden: ${OUT_ROOT}/instruction_golden/instruction_golden_report.txt"
  echo "  public NVIDIA: ${PUBLIC_NVIDIA_OUT}/firmware_profile_report.txt"
  echo "  public Panasonic: ${PUBLIC_PANASONIC_OUT}/firmware_profile_report.txt"
  echo "  timings: ${TIMINGS_FILE}"
  echo "  total wall seconds: ${TOTAL_DURATION}"
  echo
  echo "Stage timings:"
  cat "${TIMINGS_FILE}"
} | tee "${GATE_REPORT}"

echo "Wrote: ${GATE_REPORT}"
