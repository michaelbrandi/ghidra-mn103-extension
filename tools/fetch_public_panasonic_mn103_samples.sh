#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"
WS_DIR="$(cd "${EXT_DIR}/.." && pwd)"

OUT_DIR="${1:-${WS_DIR}/tmp_mn103_public_panasonic_samples}"
CACHE_DIR="${CACHE_DIR:-${WS_DIR}/tmp_mn103_cache/panasonic}"

mkdir -p "${OUT_DIR}" "${CACHE_DIR}"

download_zip() {
  local url="$1"
  local out="$2"
  if [[ ! -f "${out}" ]]; then
    echo "Downloading ${url}"
    curl -fsSL "${url}" -o "${out}"
  fi
}

extract_member() {
  local zip_path="$1"
  local member="$2"
  local out_name="$3"
  python3 - "$zip_path" "$member" "$OUT_DIR/$out_name" <<'PY'
import sys, zipfile
zip_path, member, out_path = sys.argv[1:4]
with zipfile.ZipFile(zip_path) as zf:
    try:
        data = zf.read(member)
    except KeyError as exc:
        raise SystemExit(f"missing member {member} in {zip_path}") from exc
with open(out_path, "wb") as f:
    f.write(data)
print(f"Wrote: {out_path} ({len(data)} bytes)")
PY
}

cat > "${OUT_DIR}/sources.tsv" <<'EOF'
corpus	file	url	member
FP3	panasonic_dmc_fp3_v13.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fp3/FP3__V13.zip	FP3__V13.bin
FZ80	panasonic_dc_fz80_v11.bin	https://av.jpn.support.panasonic.com/support/share2/eww/com/dsc/fz80_81_82_83_85/FZ80_V11.zip	FZ80_V11.bin
HX-A1M	panasonic_hx_a1m_sdcardv.bin	https://av.jpn.support.panasonic.com/support/share/eww/jp/video/a1h/A1_V11.zip	SD_CarDV.bin
HX-A1M	panasonic_hx_a1m_sdfwcode.bin	https://av.jpn.support.panasonic.com/support/share/eww/jp/video/a1h/A1_V11.zip	SdFwCode.bin
HX-A100	panasonic_hx_a100_update_hdc.bin	https://av.jpn.support.panasonic.com/support/share/eww/jp/video/a100/A100_V12.zip	UPDATE.HDC
HC-MDH3	panasonic_hc_mdh3_update_hdc.bin	https://av.jpn.support.panasonic.com/support/share2/eww/en/e_cam/mdh3/MDH3_V110.zip	UPDATE.HDC
EOF

while IFS=$'\t' read -r corpus file url member; do
  [[ "${corpus}" == "corpus" ]] && continue
  zip_name="$(basename "${url}")"
  zip_path="${CACHE_DIR}/${zip_name}"
  download_zip "${url}" "${zip_path}"
  extract_member "${zip_path}" "${member}" "${file}"
done < "${OUT_DIR}/sources.tsv"

cat > "${OUT_DIR}/README.sources.txt" <<EOF
Public Panasonic product firmware corpus
========================================

These are official product firmware update packages from Panasonic support pages.
They are not encrypted update wrappers; the first bytes and the Ghidra imports
show normal firmware containers with usable binary payloads.

Sample sources:
  - DMC-FP3 firmware update page
  - DC-FZ80/FZ81/FZ82/FZ83 firmware update page
  - HX-A1M firmware update page
  - HX-A100 firmware update page
  - HC-MDH3 firmware update page

Package URLs and extracted members are listed in sources.tsv.
EOF

echo "Fetched Panasonic product corpus into: ${OUT_DIR}"
