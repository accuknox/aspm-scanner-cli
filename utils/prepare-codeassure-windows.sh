#!/bin/bash
# Build a Windows CodeAssure exe (PyInstaller) and pack it as
# codeassure-windows-amd64.tar.gz with layout:
#   codeassure/codeassure.exe
#
# Must run on Windows (GitHub windows-latest). PyInstaller cannot cross-compile.
set -euo pipefail

if [[ "${RUNNER_OS:-}" != "Windows" && "$(uname -s)" != MINGW* && "$(uname -s)" != MSYS* && "$(uname -s)" != *NT* ]]; then
  echo "This script must run on Windows (PyInstaller cannot cross-compile)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}"
CODEASSURE_REPO="${CODEASSURE_REPO:-https://github.com/accuknox/codeassure-cli.git}"
CODEASSURE_VERSION="${CODEASSURE_VERSION:-v0.1.1}"
WORK="${SCRIPT_DIR}/temp_codeassure_windows"
DIST_STAGE="${WORK}/stage"

rm -rf "$WORK"
mkdir -p "$DIST_STAGE/codeassure"

echo "=== Cloning codeassure-cli ${CODEASSURE_VERSION} ==="
git clone --branch "$CODEASSURE_VERSION" --depth 1 "$CODEASSURE_REPO" "$WORK/src"
cd "$WORK/src"

python -m pip install --upgrade pip
python -m pip install -e ".[build]"
python -m PyInstaller codeassure.spec --clean

if [[ -f dist/codeassure.exe ]]; then
  cp dist/codeassure.exe "$DIST_STAGE/codeassure/codeassure.exe"
elif [[ -f dist/codeassure ]]; then
  cp dist/codeassure "$DIST_STAGE/codeassure/codeassure.exe"
else
  echo "PyInstaller did not produce dist/codeassure.exe" >&2
  ls -la dist || true
  exit 1
fi

cd "$OUT_DIR"
tar -czf "${OUT_DIR}/codeassure-windows-amd64.tar.gz" -C "$DIST_STAGE" codeassure
rm -rf "$WORK"

echo "✅ codeassure-windows-amd64.tar.gz"
ls -lah "${OUT_DIR}/codeassure-windows-amd64.tar.gz"
