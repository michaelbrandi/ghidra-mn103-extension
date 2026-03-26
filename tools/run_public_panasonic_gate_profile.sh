#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

OUT_DIR="${1:-${WS_DIR}/tmp_mn103_headless/public_panasonic_profile}"
CORPUS_DIR="${2:-${WS_DIR}/tmp_mn103_public_panasonic_samples}"
SUBSET_DIR="${3:-${WS_DIR}/tmp_mn103_public_panasonic_gate_samples}"

"${TOOLS_DIR}/fetch_public_panasonic_mn103_samples.sh" "${CORPUS_DIR}"

rm -rf "${SUBSET_DIR}"
mkdir -p "${SUBSET_DIR}"

cat > "${SUBSET_DIR}/sources.tsv" <<'EOF'
corpus	file	url	member
FP3	panasonic_dmc_fp3_v13.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fp3/FP3__V13.zip	FP3__V13.bin
HX-A1M	panasonic_hx_a1m_sdcardv.bin	https://av.jpn.support.panasonic.com/support/share/eww/jp/video/a1h/A1_V11.zip	SD_CarDV.bin
HX-A1M	panasonic_hx_a1m_sdfwcode.bin	https://av.jpn.support.panasonic.com/support/share/eww/jp/video/a1h/A1_V11.zip	SdFwCode.bin
EOF

cat > "${SUBSET_DIR}/README.sources.txt" <<'EOF'
Representative Panasonic product firmware regression subset
===========================================================

This directory is a smaller gate-friendly subset of the full optional
Panasonic product corpus. It keeps the regression pass practical while still
covering real product firmware images from Panasonic support pages.

Full corpus files are fetched into the sibling directory passed as CORPUS_DIR
by `fetch_public_panasonic_mn103_samples.sh`.
EOF
while IFS=$'\t' read -r corpus file url member; do
  [[ "${corpus}" == "corpus" ]] && continue
  cp -f "${CORPUS_DIR}/${file}" "${SUBSET_DIR}/${file}"
done < "${SUBSET_DIR}/sources.tsv"

"${TOOLS_DIR}/run_firmware_profile.sh" "${SUBSET_DIR}" "${OUT_DIR}"
