#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

OUT_DIR="${1:-${WS_DIR}/tmp_mn103_public_nvidia_samples}"
PINNED_SHA="2237b9924a5e77308fdf2f5850f84b78074d21fc"
BASE_URL="https://raw.githubusercontent.com/NVIDIA/linux-firmware/${PINNED_SHA}"

mkdir -p "${OUT_DIR}"

cat > "${OUT_DIR}/sources.tsv" <<EOF
nvidia_gp104_gr_fecs_inst.bin	${BASE_URL}/nvidia/gp104/gr/fecs_inst.bin	22760
nvidia_gp104_gr_gpccs_inst.bin	${BASE_URL}/nvidia/gp104/gr/gpccs_inst.bin	13307
nvidia_gp102_gr_fecs_inst.bin	${BASE_URL}/nvidia/gp102/gr/fecs_inst.bin	20927
nvidia_gp102_gr_gpccs_inst.bin	${BASE_URL}/nvidia/gp102/gr/gpccs_inst.bin	13307
nvidia_tu102_gr_fecs_inst.bin	${BASE_URL}/nvidia/tu102/gr/fecs_inst.bin	29080
nvidia_tu102_gr_gpccs_inst.bin	${BASE_URL}/nvidia/tu102/gr/gpccs_inst.bin	12717
EOF

rm -f "${OUT_DIR}"/*.bin

while IFS=$'\t' read -r name url size; do
  [[ -z "${name:-}" ]] && continue
  [[ "${name}" == \#* ]] && continue

  echo "Fetching ${name} (${size} bytes expected)..."
  curl -fsSL "${url}" -o "${OUT_DIR}/${name}"
done < "${OUT_DIR}/sources.tsv"

cat > "${OUT_DIR}/README.sources.txt" <<EOF
Public NVIDIA MN103 firmware corpus
===================================

Source repository:
  https://github.com/NVIDIA/linux-firmware

Pinned snapshot:
  ${PINNED_SHA}

Fetched files:
$(awk -F'\t' '{printf "  - %s (%s bytes)\n", $1, $3}' "${OUT_DIR}/sources.tsv")

These blobs are used as a broader public validation corpus for the MN103
Ghidra language extension.
EOF

echo "Fetched public NVIDIA corpus into: ${OUT_DIR}"
