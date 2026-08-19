#!/bin/bash
# Package macOS scanner tools (Apple Silicon arm64 + Intel x86_64) into AccuKnox-shaped tarballs.
# Can run on Linux CI — only downloads and re-packs upstream Darwin binaries.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}"
ARCHES=("arm64" "x86_64")

CHECKOV_VERSION="3.2.458"
TRUFFLEHOG_VERSION="3.90.3"
TRIVY_VERSION="0.69.3"
GITLEAKS_VERSION="8.24.2"
SONAR_SCANNER_VERSION="7.1.0.4889"
OPENGREP_VERSION="v1.22.0"
RULES_COMMIT="f1d2b562b414783763fd02a6ed2736eaed622efa"

package_for_arch() {
  local ARCH="$1"
  local WORK="temp_darwin_${ARCH}"
  rm -rf "$WORK"
  mkdir -p "$WORK"
  pushd "$WORK" >/dev/null

  echo "=== Packaging Darwin ${ARCH} ==="

  # --- iac (Checkov) ---
  # Upstream asset checkov_darwin_X86_64.zip is mislabeled and contains an arm64 Mach-O.
  # Only package it for arm64. Intel Mac local install uses pip (see ToolDownloader).
  if [[ "$ARCH" == "arm64" ]]; then
    curl -fsSL -o checkov.zip \
      "https://github.com/bridgecrewio/checkov/releases/download/${CHECKOV_VERSION}/checkov_darwin_X86_64.zip"
    unzip -o -q checkov.zip
    cp dist/checkov iac
    chmod +x iac
    tar -czf "${OUT_DIR}/iac-darwin-${ARCH}.tar.gz" iac
    echo "✅ iac-darwin-${ARCH}.tar.gz"
  else
    echo "⚠️  Skipping iac-darwin-${ARCH}.tar.gz (no usable Checkov standalone for Intel; CLI uses pip)"
  fi

  # --- secret (TruffleHog) ---
  local HOG_ARCH="arm64"
  [[ "$ARCH" == "x86_64" ]] && HOG_ARCH="amd64"
  curl -fsSL -O \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_darwin_${HOG_ARCH}.tar.gz"
  tar -xzf "trufflehog_${TRUFFLEHOG_VERSION}_darwin_${HOG_ARCH}.tar.gz"
  cp trufflehog secret
  chmod +x secret
  tar -czf "${OUT_DIR}/secret-darwin-${ARCH}.tar.gz" secret
  echo "✅ secret-darwin-${ARCH}.tar.gz"

  # --- container (Aqua Trivy; AccuKnox fork has no Darwin builds) ---
  local TRIVY_ARCH="ARM64"
  [[ "$ARCH" == "x86_64" ]] && TRIVY_ARCH="64bit"
  curl -fsSL -O \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_macOS-${TRIVY_ARCH}.tar.gz"
  tar -xzf "trivy_${TRIVY_VERSION}_macOS-${TRIVY_ARCH}.tar.gz" trivy
  cp trivy container
  chmod +x container
  tar -czf "${OUT_DIR}/container-darwin-${ARCH}.tar.gz" container
  echo "✅ container-darwin-${ARCH}.tar.gz"

  # --- gitleaks ---
  local GL_ARCH="arm64"
  [[ "$ARCH" == "x86_64" ]] && GL_ARCH="x64"
  curl -fsSL -O \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_darwin_${GL_ARCH}.tar.gz"
  tar -xzf "gitleaks_${GITLEAKS_VERSION}_darwin_${GL_ARCH}.tar.gz"
  chmod +x gitleaks
  tar -czf "${OUT_DIR}/gitleaks-darwin-${ARCH}.tar.gz" gitleaks
  echo "✅ gitleaks-darwin-${ARCH}.tar.gz"

  # --- sast (OpenGrep + rules) ---
  local OG_BIN="opengrep_osx_arm64"
  [[ "$ARCH" == "x86_64" ]] && OG_BIN="opengrep_osx_x86"
  mkdir -p sast
  curl -fsSL -o sast/sast \
    "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${OG_BIN}"
  chmod +x sast/sast
  mkdir -p rules_extract
  curl -fsSL \
    "https://api.github.com/repos/opengrep/opengrep-rules/tarball/${RULES_COMMIT}" \
    | tar -xz -C rules_extract --strip-components=1
  rm -rf rules_extract/.pre-commit-config.yaml rules_extract/stats rules_extract/.github 2>/dev/null || true
  mv rules_extract sast/rules
  tar -czf "${OUT_DIR}/sast-darwin-${ARCH}.tar.gz" sast
  echo "✅ sast-darwin-${ARCH}.tar.gz"

  # --- sq-sast (SonarScanner) ---
  local SQ_ARCH="aarch64"
  [[ "$ARCH" == "x86_64" ]] && SQ_ARCH="x64"
  curl -fsSL -O \
    "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-macosx-${SQ_ARCH}.zip"
  unzip -o -q "sonar-scanner-cli-${SONAR_SCANNER_VERSION}-macosx-${SQ_ARCH}.zip"
  EXTRACTED="$(find . -maxdepth 1 -type d -name 'sonar-scanner*' | head -n 1)"
  mv "$EXTRACTED" sq-sast
  tar -czf "${OUT_DIR}/sq-sast-darwin-${ARCH}.tar.gz" sq-sast
  echo "✅ sq-sast-darwin-${ARCH}.tar.gz"

  popd >/dev/null
  rm -rf "$WORK"
}

for arch in "${ARCHES[@]}"; do
  package_for_arch "$arch"
done

echo "🎉 Darwin scanner tarballs ready in ${OUT_DIR}"
ls -lah "${OUT_DIR}"/*-darwin-*.tar.gz
