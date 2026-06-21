#!/usr/bin/env bash
set -euo pipefail

GHIDRA_INSTALL_DIR="${1:-${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}}"
ZIP_PATH="${2:-./dist/ghidra-mn103-extension.zip}"

APP_EXT_PARENT="${GHIDRA_INSTALL_DIR}/Ghidra/Extensions"
LEGACY_EXT_PARENT="${GHIDRA_INSTALL_DIR}/Extensions"
APP_EXTENSION="${APP_EXT_PARENT}/ghidra-mn103"
LEGACY_EXTENSION="${LEGACY_EXT_PARENT}/ghidra-mn103"

if [[ ! -f "${ZIP_PATH}" ]]; then
  echo "error: extension package not found at ${ZIP_PATH}" >&2
  exit 1
fi

rm -rf "${APP_EXTENSION}" "${LEGACY_EXTENSION}"
mkdir -p "${APP_EXT_PARENT}" "${LEGACY_EXT_PARENT}"
unzip -q "${ZIP_PATH}" -d "${APP_EXT_PARENT}"

INSTALLED_SPEC="$(find "${APP_EXT_PARENT}" -type f -path '*/data/languages/mn103.slaspec' | head -n 1)"
if [[ -z "${INSTALLED_SPEC}" ]]; then
  echo "error: installed extension does not contain data/languages/mn103.slaspec" >&2
  exit 1
fi

INSTALLED_ROOT="$(cd "$(dirname "${INSTALLED_SPEC}")/../.." && pwd)"
if [[ "${INSTALLED_ROOT}" != "${APP_EXTENSION}" ]]; then
  rm -rf "${APP_EXTENSION}"
  cp -R "${INSTALLED_ROOT}" "${APP_EXTENSION}"
fi

cp -R "${APP_EXTENSION}" "${LEGACY_EXTENSION}"
test -f "${APP_EXTENSION}/data/languages/mn103.slaspec"
test -f "${LEGACY_EXTENSION}/data/languages/mn103.slaspec"

echo "Installed app extension into: ${APP_EXTENSION}"
echo "Mirrored app extension into: ${LEGACY_EXTENSION}"
