#!/usr/bin/env bash
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$(cd "${TOOLS_DIR}/.." && pwd)"

GHIDRA_INSTALL_DIR="${1:-${GHIDRA_INSTALL_DIR:-${HOME}/Applications/ghidra_12.0.4_PUBLIC}}"
USER_HOME_ROOT="${2:-${GHIDRA_USER_HOME:-${HOME}}}"

SOURCE_EXTENSION="${GHIDRA_INSTALL_DIR}/Extensions/ghidra-mn103"

if [[ ! -d "${SOURCE_EXTENSION}" ]]; then
  echo "error: installed extension directory not found at ${SOURCE_EXTENSION}" >&2
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
cp -R "${SOURCE_EXTENSION}" "${TARGET_EXTENSION}"

echo "Installed extension into: ${TARGET_EXTENSION}"
