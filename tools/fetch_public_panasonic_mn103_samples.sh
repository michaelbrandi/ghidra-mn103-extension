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
  if [[ ! -s "${out}" ]]; then
    echo "Downloading ${url}"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "${url}" -o "${out}"
    else
      python3 - "${url}" "${out}" <<'PY'
import sys
from urllib.request import Request, urlopen

url, out_path = sys.argv[1:3]
req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urlopen(req, timeout=120) as resp, open(out_path, "wb") as out:
    out.write(resp.read())
PY
    fi
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
FS15	panasonic_dmc_fs15_v13.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fs15/FS15_V13.zip	FS15_130.bin
FT3	panasonic_dmc_ft3_v12.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/ft3_ts3/FT3__V12.zip	FT3__V12.bin
HX-A1M	panasonic_hx_a1m_sdcardv.bin	https://av.jpn.support.panasonic.com/support/share/eww/jp/video/a1h/A1_V11.zip	SD_CarDV.bin
HX-A1M	panasonic_hx_a1m_sdfwcode.bin	https://av.jpn.support.panasonic.com/support/share/eww/jp/video/a1h/A1_V11.zip	SdFwCode.bin
HX-A100	panasonic_hx_a100_update_hdc.bin	https://av.jpn.support.panasonic.com/support/share/eww/jp/video/a100/A100_V12.zip	UPDATE.HDC
HC-MDH3	panasonic_hc_mdh3_update_hdc.bin	https://av.jpn.support.panasonic.com/support/share2/eww/en/e_cam/mdh3/MDH3_V110.zip	UPDATE.HDC
LX3	panasonic_dmc_lx3_v22.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/lx3/LX3_V22.zip	LX3__220.bin
LX5	panasonic_dmc_lx5_v20.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/lx5/LX5__V20.zip	LX5__V20.bin
TZ4	panasonic_dmc_tz4_v12.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/tz4_tz5/TZ4_V12.zip	TZ4_a.bin
TZ7	panasonic_dmc_tz7_v13.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/tz7_zs3/TZ7_V13.zip	TZ7__130.bin
ZS3	panasonic_dmc_zs3_v13.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/tz7_zs3/ZS3_V13.zip	TZ7__130.bin
ZX3	panasonic_dmc_zx3_v11.bin	https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/zx3_zr3/ZX3_V11.zip	ZX3__V11.bin
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
In quick checks they show structured update headers such as UPD and Panasonic
markers, plus readable strings inside the payloads. I did not find evidence of
encrypted update blobs in the samples below.

Sample sources:
  - DMC-FP3 firmware update page
  - DC-FZ80/FZ81/FZ82/FZ83 firmware update page
  - DMC-FS15 firmware update page
  - DMC-FT3 firmware update page
  - HX-A1M firmware update page
  - HX-A100 firmware update page
  - HC-MDH3 firmware update page
  - DMC-LX3 firmware update page
  - DMC-LX5 firmware update page
  - DMC-TZ4/TZ5 firmware update page
  - DMC-TZ7/ZS3 firmware update page
  - DMC-ZX3 firmware update page

Package URLs and extracted members are listed in sources.tsv.
EOF

echo "Fetched Panasonic product corpus into: ${OUT_DIR}"
