#!/bin/bash
# Package Windows (x86_64) scanner tools into AccuKnox-shaped archives.
# Can run on Linux CI — only downloads and re-packs upstream Windows binaries.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}"
WORK="temp_windows_amd64"

CHECKOV_VERSION="3.2.458"
TRUFFLEHOG_VERSION="3.90.3"
TRIVY_VERSION="0.69.3"
GITLEAKS_VERSION="8.24.2"
SONAR_SCANNER_VERSION="7.1.0.4889"
OPENGREP_VERSION="v1.22.0"
RULES_COMMIT="f1d2b562b414783763fd02a6ed2736eaed622efa"

rm -rf "$WORK"
mkdir -p "$WORK"
pushd "$WORK" >/dev/null

echo "=== Packaging Windows amd64 scanners ==="

# --- iac (Checkov) ---
curl -fsSL -o checkov.zip \
  "https://github.com/bridgecrewio/checkov/releases/download/${CHECKOV_VERSION}/checkov_windows_X86_64.zip"
unzip -o -q checkov.zip
if [[ -f dist/checkov.exe ]]; then
  cp dist/checkov.exe iac.exe
elif [[ -f checkov.exe ]]; then
  cp checkov.exe iac.exe
else
  echo "checkov.exe not found in archive" >&2
  exit 1
fi
tar -czf "${OUT_DIR}/iac-windows-amd64.tar.gz" iac.exe
echo "✅ iac-windows-amd64.tar.gz"

# --- secret (TruffleHog) ---
curl -fsSL -O \
  "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_windows_amd64.tar.gz"
tar -xzf "trufflehog_${TRUFFLEHOG_VERSION}_windows_amd64.tar.gz"
cp trufflehog.exe secret.exe 2>/dev/null || cp trufflehog secret.exe
tar -czf "${OUT_DIR}/secret-windows-amd64.tar.gz" secret.exe
echo "✅ secret-windows-amd64.tar.gz"

# --- container (Aqua Trivy) ---
curl -fsSL -O \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_windows-64bit.zip"
unzip -o -q "trivy_${TRIVY_VERSION}_windows-64bit.zip"
cp trivy.exe container.exe
tar -czf "${OUT_DIR}/container-windows-amd64.tar.gz" container.exe
echo "✅ container-windows-amd64.tar.gz"

# --- gitleaks ---
curl -fsSL -O \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_windows_x64.zip"
unzip -o -q "gitleaks_${GITLEAKS_VERSION}_windows_x64.zip"
tar -czf "${OUT_DIR}/gitleaks-windows-amd64.tar.gz" gitleaks.exe
echo "✅ gitleaks-windows-amd64.tar.gz"

# --- sast (OpenGrep + rules) ---
mkdir -p sast
curl -fsSL -o sast/sast.exe \
  "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_windows_x86.exe"
mkdir -p rules_extract
curl -fsSL \
  "https://api.github.com/repos/opengrep/opengrep-rules/tarball/${RULES_COMMIT}" \
  | tar -xz -C rules_extract --strip-components=1
rm -rf rules_extract/.pre-commit-config.yaml rules_extract/stats rules_extract/.github 2>/dev/null || true
mv rules_extract sast/rules
tar -czf "${OUT_DIR}/sast-windows-amd64.tar.gz" sast
echo "✅ sast-windows-amd64.tar.gz"

# --- sq-sast (SonarScanner) ---
curl -fsSL -O \
  "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-windows-x64.zip"
unzip -o -q "sonar-scanner-cli-${SONAR_SCANNER_VERSION}-windows-x64.zip"
EXTRACTED="$(find . -maxdepth 1 -type d -name 'sonar-scanner*' | head -n 1)"
mv "$EXTRACTED" sq-sast
tar -czf "${OUT_DIR}/sq-sast-windows-amd64.tar.gz" sq-sast
echo "✅ sq-sast-windows-amd64.tar.gz"

popd >/dev/null
rm -rf "$WORK"

echo "🎉 Windows scanner archives ready in ${OUT_DIR}"
ls -lah "${OUT_DIR}"/*-windows-*.tar.gz
