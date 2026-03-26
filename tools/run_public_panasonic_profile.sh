#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

OUT_DIR="${1:-${WS_DIR}/tmp_mn103_headless/public_panasonic_profile}"
CORPUS_DIR="${2:-${WS_DIR}/tmp_mn103_public_panasonic_samples}"

"${TOOLS_DIR}/fetch_public_panasonic_mn103_samples.sh" "${CORPUS_DIR}"
"${TOOLS_DIR}/run_firmware_profile.sh" "${CORPUS_DIR}" "${OUT_DIR}"
