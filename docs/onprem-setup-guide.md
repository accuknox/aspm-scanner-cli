# On-Prem Setup Guide

This guide is for running `accuknox-aspm-scanner` in restricted, self-hosted, or air-gapped environments.

It focuses on the current behavior of the CLI as implemented today, including limitations and practical workarounds for on-prem setups.

## Recommended Approach

Use one of these operating models:

- Local mode: install the required scanner tools first with `accuknox-aspm-scanner tool install ...`, then run scans without `--container-mode`.
- Container mode: run scans with `--container-mode` and provide scanner images from an internal registry when needed.
- Offline artifact collection: use `--skip-upload --keep-results` so the scan runs locally and preserves the generated result files.

For most on-prem setups:

- Use `--skip-upload` unless the control plane endpoint is already reachable from the environment.
- Use `--keep-results` so output artifacts remain available for review.
- Prefer `--container-mode` for DAST.
- Treat `SCAN_IMAGE` as a per-scan override, not a global environment default for all scanner types.

## Prerequisites

### Local mode

- Python environment with the CLI installed.
- Required scanner tools installed with `accuknox-aspm-scanner tool install --type <tool>`.
- Linux is the best-supported local mode today.

Tool locations:

- User installs: `~/.local/bin/accuknox/`
- Debian package installs: `/usr/share/accuknox-aspm-scanner/tools`

### Container mode

- Docker daemon access from the machine running the CLI.
- Ability to pull scanner images from a reachable registry.
- If using an internal registry, export `SCAN_IMAGE` or `CODEASSURE_IMAGE` before the relevant scan.

### Optional upload to AccuKnox

These are only required when not using `--skip-upload`:

- `ACCUKNOX_ENDPOINT`
- `ACCUKNOX_LABEL`
- `ACCUKNOX_TOKEN`
- `ACCUKNOX_PROJECT_NAME` for SBOM uploads (legacy `ACCUKNOX_PROJECT` also accepted). Not required for container vulnerability scans.

## Installation Patterns

### Connected environment

Install the CLI from the GitHub release wheel:

```bash
pip install https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.14.2/accuknox_aspm_scanner-0.14.2-py3-none-any.whl
```

### Restricted or on-prem environment

Install the Debian package from the provided release artifact:

```bash
sudo dpkg -i accuknox-aspm-scanner_<version>.deb
```

### Install local scanner tools

Install all local tools:

```bash
accuknox-aspm-scanner tool install --all
```

Install a specific local tool:

```bash
accuknox-aspm-scanner tool install --type iac
```

Update a specific local tool:

```bash
accuknox-aspm-scanner tool update --type iac
```

Supported tool types:

- `iac`
- `sast`
- `sq-sast`
- `secret`
- `container`
- `dast`
- `codeassure`

## Common Environment Variables

- `DEBUG=TRUE`: enable verbose logs.
- `SOFT_FAIL=TRUE`: make soft-fail the default.
- `KEEP_RESULTS=TRUE`: preserve result files after completion.
- `SCAN_IMAGE=<image>`: override the current scanner image in container mode.
- `CODEASSURE_IMAGE=<image>`: override the SAST AI analysis image.

Important: `SCAN_IMAGE` is shared across multiple scanner implementations. Set it only for the scan you are about to run, then unset or replace it before another scan type.

## Copy-Paste Commands

### IaC scan with mirrored Checkov image

```bash
export SCAN_IMAGE=registry.local/bridgecrew/checkov:3.2.458
accuknox-aspm-scanner scan --skip-upload --keep-results iac --command "-d ." --container-mode
```

### SAST scan with local tool install

```bash
accuknox-aspm-scanner tool install --type sast
accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ."
```

### Secret scan with mirrored TruffleHog image

```bash
export SCAN_IMAGE=registry.local/trufflesecurity/trufflehog:3.90.3
accuknox-aspm-scanner scan --skip-upload --keep-results secret --command "git file://." --container-mode
```

### Container scan with mirrored Trivy image

```bash
export SCAN_IMAGE=registry.local/accuknox/trivy:0.69.3
accuknox-aspm-scanner scan --skip-upload --keep-results container --command "image nginx:latest" --container-mode
```

### Filesystem SBOM (application classifier)

Run from the repository root so the checkout is mounted at `/workdir` inside the Trivy container. Use an AccuKnox SBOM project with classifier `application` (not `container`).

```bash
export SCAN_IMAGE=registry.local/accuknox/trivy:0.69.3
accuknox-aspm-scanner scan --skip-upload --keep-results --project-name demo-project container \
  --command "filesystem ." --generate-sbom --container-mode
```

### DAST scan with mirrored ZAP image

```bash
export SCAN_IMAGE=registry.local/zaproxy/zap-stable:2.16.1
accuknox-aspm-scanner scan --skip-upload --keep-results dast --command "zap-baseline.py -t http://example.com/ -I" --container-mode
```

### SonarQube SAST scan against self-hosted SonarQube

```bash
export SCAN_IMAGE=registry.local/sonarsource/sonar-scanner-cli:11.4
accuknox-aspm-scanner scan --skip-upload --keep-results sq-sast --command "-Dsonar.projectKey=my-project -Dsonar.host.url=https://sonarqube.internal -Dsonar.token=$SONAR_TOKEN" --container-mode
```

### Upload to AccuKnox when the endpoint is reachable

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=onprem \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan --softfail sast --command "scan ."
```

## Result Files And Retention

The CLI writes scan outputs to fixed filenames so it can upload them consistently. Common result files include:

- IaC: `results_json.json`
- SAST: `results.json`
- Secret: `results.jsonl`
- Container: `results.json`
- DAST: `results.json`

Operational note:

- If you upload results, files are deleted after upload unless `--keep-results` is set.
- If you use `--skip-upload`, files are still deleted unless `--keep-results` is set.
- Some scanners normalize output-related flags inside `--command`, so do not rely on custom output filenames or report flags being preserved.

For on-prem validation, prefer:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results <scan-name> --command "<scanner args>"
```

## Troubleshooting

### Upload configuration errors

If upload is enabled, the CLI requires `ACCUKNOX_ENDPOINT`, `ACCUKNOX_LABEL`, and `ACCUKNOX_TOKEN` unless those are passed as flags before the scan name.

Workaround:

- Add `--skip-upload` for standalone testing.
- Or export the required environment variables before running the scan.

### Tool not found in local mode

If a local scan fails because the tool is missing:

- Run `accuknox-aspm-scanner tool install --type <tool>`
- Or switch to `--container-mode`

### Result files disappeared

The CLI deletes result files by default.

Workaround:

- Add `--keep-results`
- Or set `KEEP_RESULTS=TRUE`

### Docker access issues

Container mode requires a working Docker daemon and image pull access.

Workaround:

- Verify `docker run` works from the same host account.
- Mirror the required images into an internal registry.
- Export `SCAN_IMAGE` to the internal image before running the scan.

## Current Limitations And Workarounds

### `sq-sast --skip-sonar-scan` still requires `--command`

The parser currently requires `--command` even when `--skip-sonar-scan` is used.

Workaround:

- Still provide Sonar metadata in `--command`, especially `-Dsonar.projectKey`, `-Dsonar.host.url`, and `-Dsonar.token`, so the fetcher can retrieve results.

Example:

```bash
accuknox-aspm-scanner scan --skip-upload sq-sast --skip-sonar-scan --command "-Dsonar.projectKey=my-project -Dsonar.host.url=https://sonarqube.internal -Dsonar.token=$SONAR_TOKEN"
```

### DAST local mode is partial

The current DAST implementation does not fully support local execution for `zap-baseline.py` and `zap-full-scan.py`.

Workaround:

- Use `--container-mode` for DAST runs.

### Local tool installation is not air-gap friendly by default

`tool install` downloads artifacts directly from public sources. That means fully restricted environments need either mirrored sources or pre-provisioned tools.

Workaround:

- Use the Debian package where possible.
- Pre-stage the required tools into the expected install path.
- Prefer mirrored container images for scans that can run in container mode.

### Windows native local mode is incomplete

Windows local tool downloads are incomplete, and non-container local mode is explicitly not supported.

Workaround:

- Use Linux for local-mode testing.
- Use container mode where possible.

### Upload TLS and enterprise network support are limited

The current upload path disables SSL verification and does not provide first-class flags for custom CA bundles, proxy settings, or mTLS.

Workaround:

- Prefer `--skip-upload` in isolated environments.
- If upload is required, validate control-plane connectivity early.
- Document any proxy or CA requirements externally for the environment because the CLI does not currently expose dedicated knobs for them.

### `SCAN_IMAGE` is shared across scanner types

One `SCAN_IMAGE` value does not safely cover all scanner families.

Workaround:

- Export a scanner-specific `SCAN_IMAGE` immediately before each container-mode command.
- Unset or replace it before switching scan types.

## Setup Checklist

- Install the CLI using the wheel or Debian package.
- Decide whether each scan will run in local mode or container mode.
- Mirror required container images if the environment is restricted.
- Use `--skip-upload --keep-results` for early validation.
- Validate one scan from each required category before production use.
- Test upload separately if the control plane will be part of the setup.
