# AccuKnox ASPM Scanner CLI

![AccuKnox Logo](https://accuknox.com/wp-content/uploads/accuknox-logo-2.png)

**`accuknox-aspm-scanner`** is a unified CLI for Phase-1 ASPM scans: IaC, SAST, SCA, Secret, SBOM, Container, ML model scan, API discovery, SonarQube SAST, and DAST — in CI/CD pipelines or local developer workflows.

It can upload results to the **AccuKnox ASPM Platform**, but it can also run in standalone mode for restricted or on-prem environments.

## Features

- 🚀 One CLI for Phase-1 scan types: IaC, SAST, SCA, Secret (TruffleHog/Gitleaks), SBOM, Container, ML Scan, API Discovery, SonarQube SAST, and DAST
- 🔄 Supports both local tools and containerized execution
- 🔐 Optional upload to AccuKnox ASPM
- 🧰 Works in standalone and on-prem environments
- 🧵 Supports environment-variable and flag-based configuration
- 🧩 Supports pre-commit integration

## Installation

### 1. Connected environment

Install from the GitHub release wheel:

```bash
pip install https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.14.7-rc.2/accuknox_aspm_scanner-0.14.7rc2-py3-none-any.whl
```

### 2. Restricted or on-prem environment

Install from the release `.deb` package:

```bash
sudo dpkg -i accuknox-aspm-scanner_<version>.deb
```

## Get Help

Use standard CLI help:

```bash
accuknox-aspm-scanner --help
accuknox-aspm-scanner scan --help
accuknox-aspm-scanner scan iac --help
accuknox-aspm-scanner scan sast --help
accuknox-aspm-scanner scan secret --help
accuknox-aspm-scanner scan sca --help
accuknox-aspm-scanner scan container --help
accuknox-aspm-scanner scan ml-scan --help
accuknox-aspm-scanner scan api-discovery --help
accuknox-aspm-scanner scan dast --help
accuknox-aspm-scanner scan sq-sast --help
accuknox-aspm-scanner tool --help
accuknox-aspm-scanner pre-commit --help
```

If you are running directly from local source code:

```bash
python -m aspm_cli.cli --help
```

## Environment Variables

AccuKnox upload variables are optional when `--skip-upload` is used.

- `ACCUKNOX_ENDPOINT`: Control plane URL for result upload
- `ACCUKNOX_LABEL`: Label used to associate uploaded results
- `ACCUKNOX_TOKEN`: Bearer token for upload
- `ACCUKNOX_PROJECT_NAME`: Project name used for SBOM uploads
- `ACCUKNOX_PROJECT`: Legacy fallback for project name
- `DEBUG`: Set to `TRUE` for verbose debug logs
- `SOFT_FAIL`: Set to `TRUE` to enable soft-fail by default
- `KEEP_RESULTS`: Set to `TRUE` to keep result files after scan completion
- `SCAN_IMAGE`: Override the scanner image used in container mode
- `CODEASSURE_IMAGE`: Override the AI analysis image used by SAST AI analysis
- `ACCUKNOX_ENABLE_AI_SAST`: Set to `TRUE` to enable AI-SAST per repo (alternative to `--ai-analysis`)
- `GITLEAKS_IMAGE`: Override the Gitleaks image when `--engine gitleaks`
- `ML_SCAN_IMAGE`: Override the full ModelScan image for `ml-scan` (default: `public.ecr.aws/k9v9d5v2/accuknox/ondemand_modelscan:1.0.21`)
- `ML_SCAN_IMAGE_REGISTRY` / `IMAGE_REGISTRY`: On-prem registry host; builds `{registry}/ondemand_modelscan:{tag}` when set
- `ML_SCAN_IMAGE_TAG`: Tag for ondemand_modelscan (default `1.0.21`, from platform `k8s_jobs/modelscan/release.txt`)
- `ML_SCAN_DOCKER_PLATFORM`: Docker platform for container mode (default `linux/amd64`)
- `API_DISCOVERY_IMAGE`: Override the code2api image for `api-discovery` (alias of `SCAN_IMAGE` when set)
- `CODE2API_IMAGE`: Default code2api scanner image when `SCAN_IMAGE` is unset

## Tool Management

Install all supported local tools:

```bash
accuknox-aspm-scanner tool install --all
```

Install or update a specific tool:

```bash
accuknox-aspm-scanner tool install --type iac
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
- `gitleaks`

User-level tool installs are placed under:

```bash
~/.local/bin/accuknox/
```

## How The Scan Command Works

All scans follow this structure:

```bash
accuknox-aspm-scanner scan [flags-before-the-scan-name] <scan-name> --command "<scanner-args>" [flags-after-the-scan-name]
```

Here is what each part means:

- `scan`: tells the CLI you want to run a scan
- `flags before the scan name`: these are common scan flags and work across all scan types
- `<scan-name>`: one of `iac`, `sast`, `sca`, `secret`, `container`, `ml-scan`, `api-discovery`, `dast`, or `sq-sast`
- `flags after the scan name`: these are only for the selected scanner
- `--command`: required for every scan and passed to the underlying scanner

Simple rule:

- If a flag is written before `iac`, `sast`, `secret`, `container`, `dast`, or `sq-sast`, it affects the overall scan behavior
- If a flag is written after the scan name, it affects only that scanner

Example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results iac --command "-d ." --container-mode
```

In that example:

- `--skip-upload` and `--keep-results` are flags before the scan name, so they control upload and file retention
- `iac` is the scan name
- `--command` and `--container-mode` come after `iac`, so they apply only to the IaC scanner

Important:

- `--command` is required for every scan type
- Use `--skip-upload` if you do not want to upload results
- Use `--keep-results` if you want to keep the generated artifact files
- Some output/report flags passed inside `--command` are normalized by the CLI so it can collect results consistently

Common flags used before the scan name:

- `--endpoint`
- `--label`
- `--token`
- `--project-name`
- `--skip-upload`
- `--keep-results`
- `--softfail`

If you do not use `--skip-upload`, you must provide:

- `ACCUKNOX_ENDPOINT` or `--endpoint`
- `ACCUKNOX_LABEL` or `--label`
- `ACCUKNOX_TOKEN` or `--token`

You can provide upload settings in either style:

Using environment variables:

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=POC \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan iac --command "-d ." --container-mode
```

Using flags before the scan name:

```bash
accuknox-aspm-scanner scan --endpoint cspm.accuknox.com --label POC --token abcd1234 iac --command "-d ." --container-mode
```

## Scan Reference

### IaC Scan

Use for Checkov-based IaC scanning.

Required:

- `--command`

Flags used after `iac`:

- `--container-mode`
- `--severity` — Comma-separated severities that fail the scan. Allowed: `INFO,LOW,MEDIUM,HIGH,CRITICAL`. Defaults to all.
- `--repo-url`
- `--repo-branch`

Typical `--command` value:

```bash
-d .
```

Example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results iac --command "-d ."
```

Container mode with AccuKnox upload:

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=POC \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan iac --command "-d ." --container-mode
```

### SAST Scan

Use for OpenGrep/SAST scanning.

Required:

- `--command`

Flags used after `sast`:

- `--container-mode`
- `--severity` — Comma-separated severities that fail the scan (matched on finding impact). Allowed: `LOW,MEDIUM,HIGH,CRITICAL,UNKNOWN`. Defaults to all.
- `--aiscan-severity`
- `--repo-url`
- `--commit-ref`
- `--commit-sha`
- `--pipeline-id`
- `--job-url`
- `--ai-analysis`
- `--codeassure-config`

Typical `--command` value:

```bash
scan .
```

Basic example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ."
```

With AI analysis (CLI flag or per-repo env var):

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ." --ai-analysis --aiscan-severity "HIGH,CRITICAL"
```

Per-repo AI-SAST via environment variable (e.g. GitLab CI variable):

```bash
ACCUKNOX_ENABLE_AI_SAST=TRUE accuknox-aspm-scanner scan --skip-upload sast --command "scan ." --container-mode
```

Container mode with AccuKnox upload:

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=POC \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan sast --command "scan ." --container-mode
```

### Secret Scan

Use for TruffleHog or Gitleaks secret scanning.

Required:

- `--command`

Flags used after `secret`:

- `--container-mode`
- `--engine` — `trufflehog` (default) or `gitleaks`

TruffleHog example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results secret --command "filesystem ." --container-mode
```

Gitleaks example (SARIF output; upload uses `data_type=DS` → `DroopescanParser`; findings appear as **droopescan**, not in TruffleHog secret-scan filters):

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results secret \
  --engine gitleaks \
  --command "detect --source . --report-format sarif --report-path results.json --no-banner" \
  --container-mode
```

### SCA Scan

Use for Trivy filesystem dependency vulnerability scanning (Software Composition Analysis).

Required:

- `--command`

Flags used after `sca`:

- `--container-mode`
- `--severity`

Typical `--command` value:

```bash
fs .
```

Example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results sca --command "fs ." --container-mode
```

### Container Scan

Use for Trivy-based container image vulnerability scanning and SBOM generation (image or filesystem).

Required:

- `--command`

Flags used after `container`:

- `--container-mode`
- `--generate-sbom`

Typical `--command` values:

```bash
image nginx:latest          # image vuln scan or container SBOM
filesystem .                # repo/filesystem SBOM (--generate-sbom only)
```

Vulnerability scan example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results container --command "image nginx:latest" --container-mode
```

Image SBOM (AccuKnox project classifier `container`):

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results --project-name demo-project container --command "image nginx:latest" --generate-sbom --container-mode
```

Filesystem SBOM (AccuKnox project classifier `application`; run from repo root in container mode):

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results --project-name demo-project container --command "filesystem ." --generate-sbom --container-mode
```

SBOM upload requires `--project-name` (or `ACCUKNOX_PROJECT_NAME`). `--project-name` is not required for vulnerability scans. Legacy env `ACCUKNOX_PROJECT` is also accepted.

SBOM Phase-1 capabilities:

| Capability | CLI command | Upload `data_type` |
|---|---|---|
| Generate BOM | `container --generate-sbom` | `SBOM` |
| Upload BOM | same + AccuKnox creds | `SBOM` |
| Dependency vulnerabilities | `sca --command "fs ."` | `TR` (Trivy JSON; parser classifies as SCA via `ArtifactType: filesystem`) |

SBOM generation includes vulnerability and license metadata in CycloneDX output (`--scanners vuln,license`).

Container mode with AccuKnox upload:

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=POC \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan container --command "image nginx:latest" --container-mode
```

### ML Scan

Use for static ML model scanning with **ModelScan** (`modelscan==0.8.1` inside the platform **`ondemand_modelscan`** job image). The CLI discovers model files under the `-p` path (`.pkl`, `.pt`, `.pth`, `.h5`, `.keras`, `.pb`, `.ckpt`, `.npy`), runs `modelscan scan -p <file> -r json` per file, wraps results as `ondemand_modelscan`, and uploads with artifact **`data_type=MLC`** (routes to `ModelscanParser`; findings appear in the UI as **MLChecks**).

**Pre-release:** use `--container-mode` (recommended for CI and platform parity). Local `modelscan` on `PATH` is optional for development only; release tarballs ship in a later GA.

Default container image (public mirror of platform **Modelscan Ondemand** `ondemand_modelscan:1.0.21`, `linux/amd64`):

```text
public.ecr.aws/k9v9d5v2/accuknox/ondemand_modelscan:1.0.21
```

Override with `ML_SCAN_IMAGE`, or set `IMAGE_REGISTRY` / `ML_SCAN_IMAGE_TAG` for on-prem mirrors. On Apple Silicon Macs, container mode uses `--platform linux/amd64` by default (override with `ML_SCAN_DOCKER_PLATFORM`).

Flags used after `ml-scan`:

- `--container-mode`
- `--repo-url` — used for `model_id` / `model_path` metadata
- `--commit-ref` — branch/ref in `model_path`
- `--model-name` — optional collector name in upload payload
- `--source-type` — default `github`

Default `--command`:

```bash
scan -p . -r json
```

Example (CI — scan all models in repo checkout):

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results ml-scan \
  --repo-url "${CI_PROJECT_PATH}" \
  --commit-ref "${CI_COMMIT_REF_NAME}" \
  --command "scan -p . -r json" \
  --container-mode
```

Example (single model path):

```bash
accuknox-aspm-scanner scan ml-scan \
  --command "scan -p ./models/model.pkl -r json" \
  --container-mode
```

### API Discovery Scan

Use **code2api** for static API discovery from source (internal routes, external HTTP calls, auth hints).

**Pre-release:** use `--container-mode` with the published image below. Local binary packaging (`tool install --type api-discovery`) ships in a later GA.

Default container image:

```text
public.ecr.aws/k9v9d5v2/accuknox/code2api:0.1.0
```

Default `--command`:

```bash
-path . -output results.json
```

Flags used after `api-discovery`:

- `--container-mode` (required for pre-release)
- `--repo-url` (optional metadata; defaults from git)

Example:

```bash
export SCAN_IMAGE=public.ecr.aws/k9v9d5v2/accuknox/code2api:0.1.0
accuknox-aspm-scanner scan --skip-upload --keep-results api-discovery \
  --command "-path . -output results.json" \
  --container-mode
```

Upload uses `data_type=API`. Output is code2api JSON (`internal_apis`, `external_apis`, `summary`).

### DAST Scan

Use for OWASP ZAP-based scanning.

Required:

- `--command`

Flags used after `dast`:

- `--severity-threshold`
- `--container-mode`

Typical `--command` value:

```bash
zap-baseline.py -t http://example.com/ -I
```

Recommended example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results dast --command "zap-baseline.py -t http://example.com/ -I" --container-mode
```

Container mode with AccuKnox upload:

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=POC \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan dast --command "zap-baseline.py -t http://example.com/ -I" --container-mode
```

### SonarQube SAST Scan

Use for SonarQube-based SAST plus result fetch.

Required:

- `--command`

Flags used after `sq-sast`:

- `--skip-sonar-scan`
- `--container-mode`
- `--repo-url`
- `--branch`
- `--commit-sha`
- `--pipeline-url`

Typical `--command` value:

```bash
-Dsonar.projectKey=<PROJECT_KEY> -Dsonar.host.url=<HOST_URL> -Dsonar.token=<TOKEN> -Dsonar.organization=<ORG_ID>
```

Example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results sq-sast --command "-Dsonar.projectKey=<PROJECT_KEY> -Dsonar.host.url=<HOST_URL> -Dsonar.token=<TOKEN> -Dsonar.organization=<ORG_ID>"
```

Important note:

- Even with `--skip-sonar-scan`, `--command` is still required by the current parser

Container mode with AccuKnox upload:

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=POC \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan sq-sast --command "-Dsonar.projectKey=<PROJECT_KEY> -Dsonar.host.url=<HOST_URL> -Dsonar.token=<TOKEN> -Dsonar.organization=<ORG_ID>" --container-mode
```

## Quickstart

Local mode is the default. Install the required local tool first:

```bash
accuknox-aspm-scanner tool install --type iac
accuknox-aspm-scanner scan --skip-upload --keep-results iac --command "-d ."
```

Upload example:

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=POC \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan --softfail sast --command "scan ."
```

## On-Prem / Air-Gapped Usage

For most on-prem POCs:

1. Install the CLI using the wheel or `.deb` package.
2. Decide whether each scan will run in local mode or container mode.
3. If upload is not available, use `--skip-upload`.
4. If you want local artifacts, use `--keep-results`.
5. If using container mode in a restricted environment, point `SCAN_IMAGE` to your internal registry image before each scan.

Recommended on-prem pattern:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results <scan-name> --command "<scanner args>"
```

### On-prem examples

IaC with mirrored Checkov image:

```bash
export SCAN_IMAGE=registry.local/bridgecrew/checkov:3.2.458
accuknox-aspm-scanner scan --skip-upload --keep-results iac --command "-d ." --container-mode
```

Secret scan with mirrored TruffleHog image:

```bash
export SCAN_IMAGE=registry.local/trufflesecurity/trufflehog:3.90.3
accuknox-aspm-scanner scan --skip-upload --keep-results secret --command "git file://." --container-mode
```

Container scan with mirrored Trivy image:

```bash
export SCAN_IMAGE=registry.local/accuknox/trivy:0.69.3
accuknox-aspm-scanner scan --skip-upload --keep-results container --command "image nginx:latest" --container-mode
```

DAST with mirrored ZAP image:

```bash
export SCAN_IMAGE=registry.local/zaproxy/zap-stable:2.16.1
accuknox-aspm-scanner scan --skip-upload --keep-results dast --command "zap-baseline.py -t http://example.com/ -I" --container-mode
```

SonarQube SAST against self-hosted SonarQube:

```bash
export SCAN_IMAGE=registry.local/sonarsource/sonar-scanner-cli:11.4
accuknox-aspm-scanner scan --skip-upload --keep-results sq-sast --command "-Dsonar.projectKey=my-project -Dsonar.host.url=https://sonarqube.internal -Dsonar.token=$SONAR_TOKEN" --container-mode
```

### On-prem notes

- `SCAN_IMAGE` is shared across scanner types, so set it per scan type
- `CODEASSURE_IMAGE` is used only for SAST AI analysis
- DAST is most reliable in `--container-mode`
- Result files are deleted unless `--keep-results` is used
- `tool install` downloads public artifacts, so fully restricted environments may need pre-staged local tools or mirrored images

More detailed operational notes and workarounds are available in `docs/onprem-setup-guide.md`.

## Pre-Commit Integration

Install the generated pre-commit hook:

```bash
accuknox-aspm-scanner pre-commit install
```

Remove the generated pre-commit hook:

```bash
accuknox-aspm-scanner pre-commit uninstall
```

## Debugging

Enable verbose debug mode:

```bash
DEBUG=TRUE accuknox-aspm-scanner scan --skip-upload iac --command "-d ."
```