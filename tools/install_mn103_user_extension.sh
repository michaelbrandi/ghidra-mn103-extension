#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${1:-${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}}"
USER_HOME_ROOT="${2:-${GHIDRA_USER_HOME:-${HOME}}}"

SOURCE_EXTENSION="${GHIDRA_INSTALL_DIR}/Extensions/ghidra-mn103"
PACKAGE_ZIP="${EXT_DIR}/dist/ghidra-mn103-extension.zip"
TMP_EXTRACT=""

cleanup() {
  if [[ -n "${TMP_EXTRACT}" ]]; then
    rm -rf "${TMP_EXTRACT}"
  fi
}
trap cleanup EXIT

if [[ -d "${SOURCE_EXTENSION}" ]]; then
  COPY_SOURCE="${SOURCE_EXTENSION}"
elif [[ -f "${PACKAGE_ZIP}" ]]; then
  TMP_EXTRACT="$(mktemp -d)"
  unzip -q "${PACKAGE_ZIP}" -d "${TMP_EXTRACT}"
  INSTALLED_SPEC="$(find "${TMP_EXTRACT}" -type f -path '*/data/languages/mn103.slaspec' | head -n 1)"
  if [[ -z "${INSTALLED_SPEC}" ]]; then
    echo "error: extension package does not contain data/languages/mn103.slaspec: ${PACKAGE_ZIP}" >&2
    exit 1
  fi
  COPY_SOURCE="$(cd "$(dirname "${INSTALLED_SPEC}")/../.." && pwd)"
else
  echo "error: installed extension directory not found at ${SOURCE_EXTENSION}" >&2
  echo "error: fallback extension package not found at ${PACKAGE_ZIP}" >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin)
    SETTINGS_ROOT="${USER_HOME_ROOT}/Library/ghidra/ghidra_12.0.4_PUBLIC"
    ;;
  Linux)
    SETTINGS_ROOT="${USER_HOME_ROOT}/.config/ghidra/ghidra_12.0.4_PUBLIC"
    ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    SETTINGS_ROOT="${USER_HOME_ROOT}/AppData/Roaming/ghidra/ghidra_12.0.4_PUBLIC"
    ;;
  *)
    SETTINGS_ROOT="${USER_HOME_ROOT}/.config/ghidra/ghidra_12.0.4_PUBLIC"
    ;;
esac

TARGET_EXTENSION="${SETTINGS_ROOT}/Extensions/ghidra-mn103"

mkdir -p "${SETTINGS_ROOT}/Extensions"
rm -rf "${TARGET_EXTENSION}"
cp -R "${COPY_SOURCE}" "${TARGET_EXTENSION}"

echo "Installed extension into: ${TARGET_EXTENSION}"
