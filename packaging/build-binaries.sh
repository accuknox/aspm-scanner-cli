#!/usr/bin/env bash
# Build standalone accuknox-aspm-scanner binaries (PyInstaller) for macOS and Linux.
#
#   packaging/build-binaries.sh                      # macos-arm64 linux-amd64 linux-arm64
#   packaging/build-binaries.sh macos-arm64          # one target
#   packaging/build-binaries.sh linux-amd64 linux-arm64
#
# Output (git-ignored, never committed): dist/release/
#   accuknox-aspm-scanner-darwin-arm64
#   accuknox-aspm-scanner-linux-amd64
#   accuknox-aspm-scanner-linux-arm64
#   SHA256SUMS, BUILD-INFO.txt
#
# Needs: uv (macOS builds) and Docker (Linux builds). See packaging/README.md.
set -euo pipefail

APP="accuknox-aspm-scanner"
SPEC="accuknox-aspm-scanner.spec"
PY_VERSION="3.10"
# Debian 11 keeps the glibc requirement at 2.31 so the binary also runs on
# Amazon Linux 2023 / RHEL 9 (same base as .github/workflows/release.yml).
LINUX_IMAGE="python:${PY_VERSION}-bullseye"
MAX_GLIBC="2.31"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist/release"
WORK="$ROOT/dist/.work"
TARGETS=("$@")
[ ${#TARGETS[@]} -gt 0 ] || TARGETS=(macos-arm64 linux-amd64 linux-arm64)

stage_source() {  # stage_source <dir>: clean copy of the tree without build output
  rm -rf "$1" && mkdir -p "$1"
  tar -C "$ROOT" --exclude=./dist --exclude=./build --exclude=./.git --exclude=./.venv \
    --exclude='*.egg-info' --exclude=__pycache__ -cf - . | tar -C "$1" -xf -
}

build_macos() {  # build_macos <arch>
  local arch="$1" dir="$WORK/macos-$1"
  [ "$(uname -s)" = Darwin ] || { echo "macOS targets must be built on macOS" >&2; return 1; }
  [ "$arch" = "$(uname -m)" ] || { echo "macos-$arch needs a $arch host (this is $(uname -m))" >&2; return 1; }
  stage_source "$dir"
  uv venv --quiet --python "$PY_VERSION" "$dir/.venv"
  uv pip install --quiet --python "$dir/.venv/bin/python" "$dir" pyinstaller
  (cd "$dir" && .venv/bin/pyinstaller "$SPEC" --clean --noconfirm >"$dir/pyinstaller.log" 2>&1) \
    || { tail -30 "$dir/pyinstaller.log"; return 1; }
  cp "$dir/dist/$APP" "$OUT/$APP-darwin-$arch"
}

build_linux() {  # build_linux <arch>
  local arch="$1" dir="$WORK/linux-$1"
  command -v docker >/dev/null || { echo "docker is required for Linux targets" >&2; return 1; }
  stage_source "$dir"
  docker run --rm --platform "linux/$arch" -v "$dir":/work -w /work -e PIP_ROOT_USER_ACTION=ignore -e APP="$APP" -e SPEC="$SPEC" \
    -e MAX_GLIBC="$MAX_GLIBC" "$LINUX_IMAGE" bash -euo pipefail -c '
      python -m pip install --quiet --upgrade pip
      python -m pip install --quiet . pyinstaller
      pyinstaller "$SPEC" --clean --noconfirm >pyinstaller.log 2>&1 || { tail -30 pyinstaller.log; exit 1; }
      echo "glibc symbols required: $(objdump -T dist/$APP | grep -oE "GLIBC_[0-9.]+" | sort -Vu | tr "\n" " ")"
      highest=$(objdump -T dist/$APP | grep -oE "GLIBC_[0-9.]+" | sed s/GLIBC_// | sort -V | tail -1)
      [ "$(printf "%s\n%s\n" "$highest" "$MAX_GLIBC" | sort -V | tail -1)" = "$MAX_GLIBC" ] \
        || { echo "binary needs glibc $highest (> $MAX_GLIBC)"; exit 1; }
      ./dist/$APP --help >/dev/null
    '
  cp "$dir/dist/$APP" "$OUT/$APP-linux-$arch"
}

mkdir -p "$OUT" "$WORK"
for t in "${TARGETS[@]}"; do
  echo "==> $t"
  case "$t" in
    macos-arm64)  build_macos arm64 ;;
    linux-amd64)  build_linux amd64 ;;
    linux-arm64)  build_linux arm64 ;;
    *) echo "unknown target '$t' (macos-arm64 | linux-amd64 | linux-arm64)" >&2; exit 2 ;;
  esac
done

# macOS binaries are named darwin-* to match the release assets
if [ -f "$OUT/$APP-darwin-arm64" ]; then
  "$OUT/$APP-darwin-arm64" --help >/dev/null && echo "smoke test OK: darwin-arm64"
fi

(cd "$OUT" && shasum -a 256 "$APP"-* > SHA256SUMS)
{
  echo "app:     $APP"
  echo "version: $(sed -n 's/^version *= *//p' "$ROOT/setup.cfg" | head -1)"
  echo "commit:  $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "built:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "targets: $(cd "$OUT" && ls "$APP"-* | sed "s/^$APP-//" | tr "\n" " ")"
} > "$OUT/BUILD-INFO.txt"

rm -rf "$WORK"
echo; ls -lh "$OUT"; echo; cat "$OUT/SHA256SUMS"
