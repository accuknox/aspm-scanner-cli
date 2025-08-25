#!/bin/bash
set -e

# ### 1. Checkov -> iac
# echo "=== [1/4] Downloading Checkov ==="
# CHECKOV_VERSION="3.2.458"
# CHECKOV_URL="https://github.com/bridgecrewio/checkov/releases/download/${CHECKOV_VERSION}/checkov_linux_X86_64.zip"
# CHECKOV_ZIP="checkov_linux_X86_64.zip"
# mkdir -p temp_iac_download
# cd temp_iac_download
# curl -LO "$CHECKOV_URL"
# unzip "$CHECKOV_ZIP"
# mv dist/checkov ../iac
# cd ..
# rm -rf temp_iac_download
# echo "✅ Checkov downloaded and renamed to 'iac'"

# ### 2. TruffleHog -> secret
# echo "=== [2/4] Downloading TruffleHog ==="
# TRUFFLE_VERSION="3.90.3"
# TRUFFLE_TAR="trufflehog_${TRUFFLE_VERSION}_linux_amd64.tar.gz"
# TRUFFLE_URL="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLE_VERSION}/${TRUFFLE_TAR}"
# mkdir -p temp_secret_download
# cd temp_secret_download
# curl -LO "$TRUFFLE_URL"
# tar -xzf "$TRUFFLE_TAR"
# chmod +x trufflehog
# mv trufflehog ../secret
# cd ..
# rm -rf temp_secret_download
# echo "✅ TruffleHog downloaded and renamed to 'secret'"

# ### 3. Trivy -> container.tar.gz
# echo "=== [3/4] Downloading Trivy ==="
# TRIVY_VERSION="0.65.0"
# TRIVY_URL="https://get.trivy.dev/trivy?type=tar.gz&version=${TRIVY_VERSION}&os=linux&arch=amd64"
# TRIVY_TAR="trivy.tar.gz"
# mkdir -p temp_container_download
# cd temp_container_download
# curl -L "$TRIVY_URL" -o "$TRIVY_TAR"
# tar -xzf "$TRIVY_TAR"
# chmod +x trivy
# mv trivy ../container
# cd ..
# tar -czvf container.tar.gz container
# rm -rf temp_container_download container
# echo "✅ Trivy downloaded, renamed to 'container', and archived as 'container.tar.gz'"

# ### 4. SonarScanner -> sq-sast.tar.gz
# echo "=== [4/4] Downloading SonarScanner ==="
# SQ_VERSION="7.1.0.4889"
# SQ_ZIP="sonar-scanner-cli-${SQ_VERSION}-linux-x64.zip"
# SQ_URL="https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/${SQ_ZIP}"
# SQ_FOLDER="sq-sast"
# SQ_TAR="sq-sast.tar.gz"
# mkdir -p temp_sq_sast_download
# cd temp_sq_sast_download
# curl -LO "$SQ_URL"
# unzip "$SQ_ZIP"
# EXTRACTED_DIR=$(find . -maxdepth 1 -type d -name "sonar-scanner*" | head -n 1)
# mv "$EXTRACTED_DIR" "../$SQ_FOLDER"
# cd ..
# tar -czvf "$SQ_TAR" "$SQ_FOLDER"
# rm -rf temp_sq_sast_download "$SQ_FOLDER"
# echo "✅ SonarScanner downloaded, renamed to '$SQ_FOLDER', and archived as '$SQ_TAR'"

### OpenGrep -> sast.tar.gz
echo "=== [1/1] Downloading OpenGrep Core + Rules ==="

OPENGREP_VERSION="1.8.6"
OPENGREP_TAR="opengrep-core_linux_x86.tar.gz"
OPENGREP_URL="https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${OPENGREP_TAR}"

RULES_COMMIT="f1d2b562b414783763fd02a6ed2736eaed622efa"
RULES_URL="https://api.github.com/repos/opengrep/opengrep-rules/tarball/${RULES_COMMIT}"

SAST_FOLDER="sast"
SAST_TAR="sast.tar.gz"
rm -rf "$SAST_FOLDER" temp_sast_download
mkdir -p temp_sast_download
cd temp_sast_download
curl -LO "$OPENGREP_URL"
tar -xzf "$OPENGREP_TAR"
mkdir -p "../$SAST_FOLDER"
tar -xzf "$OPENGREP_TAR"
mv opengrep-core "../$SAST_FOLDER/sast"
mkdir -p rules_extract
curl -L --silent "$RULES_URL" | tar -xz -C rules_extract --strip-components=1 2>/dev/null
rm -rf rules_extract/.pre-commit-config.yaml rules_extract/stats rules_extract/.github 2>/dev/null
mv rules_extract "../$SAST_FOLDER/rules"
cd ..
tar -czvf "$SAST_TAR" "$SAST_FOLDER"
rm -rf temp_sast_download "$SAST_FOLDER"
echo "✅ OpenGrep core + rules (commit $RULES_COMMIT) packaged into '$SAST_TAR'"

echo "🎉 All tools downloaded and prepared successfully."
