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
- 🚦 CI/CD quality gate (`gate`) that fails the pipeline on policy breaches
- 💬 PR decorator (`decorate-pr`) that posts findings as a PR review with inline comments

## Installation

### 1. Connected environment

**Requires Python 3.9+** (3.10+ recommended; matches project `Pipfile`).

Install from the GitHub release wheel:

```bash
pip install https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.15.2-rc.3/accuknox_aspm_scanner-0.15.2rc3-py3-none-any.whl
```

### 2. Restricted or on-prem environment

Install from the release `.deb` package:

```bash
sudo dpkg -i accuknox-aspm-scanner_<version>.deb
```

### 3. Native binaries (Linux, macOS, Windows)

Install the cross-platform Python wheel (same as connected environment above), or download the **platform-specific** PyInstaller binary from GitHub Releases. Do not reuse one filename across OSes:

| Platform | Release asset |
|---|---|
| Linux x86_64 | `accuknox-aspm-scanner-linux-amd64` (also published as `accuknox-aspm-scanner` for Jenkins compatibility) |
| macOS Apple Silicon | `accuknox-aspm-scanner-darwin-arm64` |
| Windows x64 | `accuknox-aspm-scanner-windows-amd64.exe` (also `accuknox-aspm-scanner.exe`) |

```bash
# Linux x86_64
curl -fL -o accuknox-aspm-scanner \
  https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.15.2-rc.3/accuknox-aspm-scanner-linux-amd64
chmod +x accuknox-aspm-scanner
```

The unprefixed `accuknox-aspm-scanner` asset is the Linux ELF only. macOS builds are published as `*-darwin-arm64` so they cannot overwrite the Linux binary.

#### macOS — both local and container modes

On macOS you can run scans either way:

1. **Local (no Docker):** install native scanner tools, then scan without `--container-mode`
2. **Container:** Docker Desktop + `--container-mode`

```bash
# Local — works on Apple Silicon (M-series) and Intel Macs
accuknox-aspm-scanner tool install --type sast
accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ."

# Or container mode
accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ." --container-mode
```

Local macOS tools supported today: `iac`, `sast`, `secret`, `container` (Trivy), `gitleaks`, `sq-sast`.  
For `dast` / `codeassure`, use `--container-mode` for now.

#### Windows — both local and container modes

1. **Local (no Docker):** install native Windows scanner tools (x64), then scan without `--container-mode`
2. **Container:** Docker Desktop + `--container-mode`

```bash
accuknox-aspm-scanner tool install --type sast
accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ."

accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ." --container-mode
```

Local Windows tools supported today: `iac`, `sast`, `secret`, `container` (Trivy), `gitleaks`, `sq-sast`, `codeassure` (x64).  
For `dast`, use `--container-mode` for now. Tools install under `%USERPROFILE%\AppData\Local\Programs\AccuKnox\`.

| Platform | Install | Local scan (`tool install`) | Container scan (`--container-mode`) |
|---|---|---|---|
| Linux | `pip` wheel, `.deb` | Supported | Supported |
| macOS (Intel + Apple Silicon) | `pip` wheel | Supported (see tools above) | Supported |
| Windows (x64) | `pip` wheel, `.exe` | Supported (see tools above) | Supported |

Notes:

- **Apple Silicon** = `arm64` / M-series; **Intel Mac** = `x86_64`. The CLI detects the CPU and installs the matching binary.
- **Windows** local install currently targets **x64** upstream binaries (standard for these scanners).
- **IaC (Checkov):** Apple Silicon uses Checkov’s Darwin standalone zip (the asset is named `X86_64` but the binary is arm64). Intel Mac installs Checkov via a dedicated pip venv (no usable x86_64 standalone zip). Other Phase-1 tools use native arm64 or x86_64 builds.

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
accuknox-aspm-scanner gate --help
accuknox-aspm-scanner decorate-pr --help
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
- `ACCUKNOX_CLI_ID`: CI/CD quality-gate run id (uuid) shared by every scanner and the `gate` step in one pipeline run. Falls back for `--cli-id`. See [CI/CD Quality Gate](#cicd-quality-gate).
- `ACCUKNOX_PROJECT_NAME`: Project name for SBOM uploads (required; created automatically if it does not exist)
- `ACCUKNOX_PROJECT`: Legacy fallback for project name
- `DEBUG`: Set to `TRUE` for verbose debug logs
- `SOFT_FAIL`: Set to `TRUE` to enable soft-fail by default
- `KEEP_RESULTS`: Set to `TRUE` to keep result files after scan completion
- `SCAN_IMAGE`: Override the scanner image used in container mode
- `SYFT_IMAGE`: Override the Syft image used with `--enrich-licenses` in container mode (default: `anchore/syft:v1.42.3`)
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
- `syft`

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
- `--cli-id` — CI/CD quality-gate run id (see [CI/CD Quality Gate](#cicd-quality-gate))
- `--repository` — CI/CD gate scope repository (e.g. `org/repo`)
- `--branch` — CI/CD gate scope branch
- `--commit-sha` — CI/CD gate scope commit SHA

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

AI analysis is **off by default**; `--ai-analysis` (or the variable below) turns it on, and `--no-ai-analysis` forces it off even when the variable is set.

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
- `--repo-url` — used for SCA asset identity (`ArtifactName`); defaults from git
- `--repo-branch` — branch used with `--repo-url`; defaults from git

Typical `--command` value:

```bash
fs .
```

Example:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results sca --command "fs ." --container-mode
```

CI example with explicit repo identity:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results sca \
  --command "fs ." \
  --repo-url "${CI_PROJECT_PATH}" \
  --repo-branch "${CI_COMMIT_REF_NAME}" \
  --container-mode
```

### Container Scan

Use for Trivy-based container image vulnerability scanning and SBOM generation (image or filesystem).

Required:

- `--command`

Flags used after `container`:

- `--container-mode`
- `--generate-sbom`
- `--enrich-licenses` (filesystem/fs SBOM only; default off)

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

Local mode (no Docker) works on Linux, macOS and Windows: install the scanner once with `accuknox-aspm-scanner tool install --type container`, then drop `--container-mode`:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results --project-name demo-project container --command "filesystem ." --generate-sbom
accuknox-aspm-scanner scan --skip-upload --keep-results --project-name demo-project container --command "image nginx:latest" --generate-sbom
```

Optional license enrich for filesystem/fs SBOM only. Trivy remains the SBOM engine (components + CVEs). With `--enrich-licenses`, Syft scans the same tree and copies normalized SPDX licenses onto matching Trivy packages (purl, then name@version). Existing Trivy licenses are not overwritten; Syft-only file components are not added. Image/rootfs SBOM and SCA are unchanged. `--enrich-licenses` on `image` / `rootfs` logs a warning and skips Syft.

```bash
accuknox-aspm-scanner tool install --type syft

accuknox-aspm-scanner scan --project-name fs-test --keep-results --softfail \
  container --command "filesystem ." --generate-sbom --enrich-licenses
```

`--container-mode` still works: Trivy image unchanged; Syft runs as `anchore/syft:v1.42.3` (override with `SYFT_IMAGE`) using the same `/workdir` mount.

SBOM upload requires `--project-name` (or `ACCUKNOX_PROJECT_NAME`). The project does not need to exist beforehand: if it is missing, AccuKnox creates it automatically from this name. `--project-name` is not required for vulnerability scans. Legacy env `ACCUKNOX_PROJECT` is also accepted.

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

Use for OWASP ZAP-based scanning. Full guide, including authenticated scans and the ZAP
Automation Framework plan format: [`docs/dast-scan.md`](docs/dast-scan.md).

Required: one of `--command` or `--zap-plan`.

Flags used after `dast`:

- `--severity-threshold`
- `--container-mode` (required for `--auth-*` and `--zap-plan`)
- `--zap-plan`: path to a ZAP Automation Framework plan (`zap.yaml`) to run as-is instead of
  `--command`/`--auth-*` — full control over jobs (spiderAjax, activeScan, passive rule config,
  auth or unauth). Mutually exclusive with `--auth-*`. Template: [`docs/examples/zap-plan-template.yaml`](docs/examples/zap-plan-template.yaml).
- `--auth-url`, `--auth-username`, `--auth-password`: log in with a real headless browser before
  spidering/scanning (works for plain HTML forms and JS/SPA logins like OWASP Juice Shop).
- `--auth-logged-in-regex`, `--auth-logged-out-regex`, `--auth-login-fallback-url`: optional
  session-verification settings for the authenticated flow above.

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

Authenticated scan:

```bash
accuknox-aspm-scanner scan dast \
  --command "zap-baseline.py -t https://example.com -m 5" \
  --container-mode \
  --auth-url "https://example.com/login" \
  --auth-username "user@example.com" \
  --auth-password "..." \
  --auth-login-fallback-url "https://example.com/account" \
  --auth-logged-in-regex "user@example\.com"
```

Bring-your-own ZAP plan (see [`docs/dast-scan.md`](docs/dast-scan.md) for the full job reference):

```bash
accuknox-aspm-scanner scan dast --zap-plan ./zap.yaml --container-mode
```

### SonarQube SAST Scan

Use for SonarQube-based SAST plus result fetch.

Required:

- `--command`

Flags used after `sq-sast`:

- `--skip-sonar-scan`
- `--container-mode`
- `--severity` — Comma-separated severities that fail the scan. Matches SonarQube issue severity (`INFO,MINOR,MAJOR,CRITICAL,BLOCKER`) and hotspot `vulnerabilityProbability` (`LOW,MEDIUM,HIGH`). Defaults to all.
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

Fail the pipeline when Critical/Blocker issues (or High hotspots) are found:

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results sq-sast \
  --command "-Dsonar.projectKey=<PROJECT_KEY> -Dsonar.host.url=<HOST_URL> -Dsonar.token=<TOKEN> -Dsonar.organization=<ORG_ID>" \
  --severity "CRITICAL,BLOCKER,HIGH"
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

## Quality Gates

A quality gate lets the **policy thresholds configured in AccuKnox** decide the build. The CLI uploads every
scan as part of one run, waits for AccuKnox to evaluate them, and then passes, warns or fails the build from
the verdict. The thresholds live in AccuKnox (policy service), not in the CLI.

### Unified run: `pipeline`

```bash
export ACCUKNOX_ENDPOINT=cspm.accuknox.com ACCUKNOX_LABEL=POC ACCUKNOX_TOKEN=<token>
export ACCUKNOX_GATE_TOKEN=<user token>   # see "Tokens" below

accuknox-aspm-scanner pipeline --scans sast,sca,secret,iac,sbom --quality-gate
```

`pipeline` runs the scans in order, uploads them under one run id, then waits for the verdict (default 5 minutes).

- `--scans`: any of `sast`, `sq-sast`, `sca`, `secret`, `iac`, `sbom` (container/filesystem SBOM).
- Per-scan options: `--sast-command` (default `scan .`), `--sca-command` (`fs .`), `--secret-command`
  (`filesystem .`), `--secret-engine`, `--iac-command` (`-d .`), `--sbom-command` (`filesystem .`),
  `--sq-sast-command`, `--container-mode`.
- Only scans that produced a result are declared to the gate, so a clean secret scan (nothing to upload)
  never leaves the gate waiting.
- With `--quality-gate`, findings no longer fail a scan step: the policy decides. Scans that cannot run or
  upload still fail the build. Without it, `pipeline` simply runs the scans one after another.
- `--fail-fast` stops at the first scan that cannot run.
- `--ai-analysis` runs AI analysis on the scans that support it (today: `sast`; off by default), with
  `--aiscan-severity`, `--codeassure-config`, `--context-graph-config` and `--graph-no-joern`. These options
  need `--ai-analysis`. Other scan types ignore it until they gain an AI step.

### Separate steps: `scan --quality-gate` + `gate`

When each scan is its own workflow step, tie them to one run and finish with `gate`:

```bash
accuknox-aspm-scanner scan --quality-gate --gate-scanners SG,TR,IAC sast --command "scan ."
accuknox-aspm-scanner scan --quality-gate --gate-scanners SG,TR,IAC sca  --command "fs ."
accuknox-aspm-scanner scan --quality-gate --gate-scanners SG,TR,IAC iac  --command "-d ."
accuknox-aspm-scanner gate
```

`--gate-scanners` must list every scan type the run uploads (`SG` sast, `SQ` sq-sast, `TR` sca/container,
`IAC`, `TruffleHog`/`DS` secret, `SBOM`). A scan that produces no result (for example a clean secret scan)
must not be listed, or the gate waits for it. Use `pipeline` to have this handled for you.

All steps of one CI run share a run id automatically (derived from the CI run on GitHub Actions, GitLab,
Bitbucket, Azure DevOps and Jenkins). Outside CI, or to override it, set `ACCUKNOX_CLI_ID` / `--cli-id`.
`scan --quality-gate` prints the run id it used.

### Outcome and exit codes

| AccuKnox verdict | Result | Exit code |
|---|---|---|
| passed | build continues | 0 |
| warning (a `warn` policy action) | build continues, warning printed | 0 |
| failed (a `block` policy action) | build fails | 1 |
| a scan could not be evaluated (unparsable scan, policy service unavailable) | build fails | 2 |
| no verdict before `--gate-timeout` | `--gate-on-timeout fail` (default) fails, `pass` continues | 2 / 0 |

`--softfail` reports a policy failure without failing the build. It does not hide scans that could not be
evaluated. The CLI prints a per-scanner table and every breached threshold, adds GitHub annotations, and
writes a summary to `$GITHUB_STEP_SUMMARY` when available.

### Options

- `--quality-gate` (or `ACCUKNOX_QUALITY_GATE=true`): enable the gate.
- `--gate-timeout <seconds>`: how long to wait for the verdict (default 300).
- `--gate-on-timeout fail|pass`: what to do if the verdict does not arrive in time (default `fail`).
- `--cli-id`, `--repository`: override the run id / the `owner/name` that policy scopes match.
- `--gate-json-file <path>` (or `ACCUKNOX_GATE_JSON_FILE`): also save the gate response to a file.

### Machine-readable result

After the verdict the CLI prints the gate response as JSON on **stdout** (logs go to stderr), between the
lines `----- quality gate response (json) -----` and `----- end quality gate response -----`:

```json
{"cli_id": "…", "state": "resolved", "exit_code": 1, "softfail": false, "detail": null,
 "response": { "status": "failed", "blocking": true, "results": {"SG": {"status": "fail", "counts": {…}, "reasons": […]}}, "overall": […] }}
```

`response` is the backend's poll response verbatim (empty when no verdict arrived); `state` is
`resolved | timeout | unsupported | rejected`. Use `--gate-json-file` for automations that should not parse stdout.

The repository and branch are detected from the CI environment or git. Policy scopes are matched against
`owner/name:branch`; set `ACCUKNOX_REPO_URL` / `ACCUKNOX_BRANCH` when they cannot be detected.

### Tokens

Uploads use `ACCUKNOX_TOKEN`. The gate API identifies a *user*, which that token may not, so `gate` and
`pipeline` use `ACCUKNOX_GATE_TOKEN` (or `--gate-token`) for polling and fall back to `ACCUKNOX_TOKEN`. If the
fallback is rejected the error says so. Keep both as CI secrets.

### GitHub Actions example

```yaml
- uses: actions/checkout@v4
- name: AccuKnox scans and quality gate
  env:
    ACCUKNOX_ENDPOINT: cspm.accuknox.com
    ACCUKNOX_LABEL: my-label
    ACCUKNOX_TOKEN: ${{ secrets.ACCUKNOX_TOKEN }}
    ACCUKNOX_GATE_TOKEN: ${{ secrets.ACCUKNOX_GATE_TOKEN }}
  run: accuknox-aspm-scanner pipeline --scans sast,sca,secret,iac --quality-gate
```

The first run for a tenant can be slow while AccuKnox downloads reference data for a scan type, so raise
`--gate-timeout` if the gate times out on first use.

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
### Scan compiled artifacts, manifests and existing SBOMs

Install the native inventory and vulnerability engines, or pass `--container-mode`:

```sh
accuknox-aspm-scanner tool install --type syft
accuknox-aspm-scanner tool install --type container

# Existing --command workflows remain supported.
accuknox-aspm-scanner scan --skip-upload --keep-results sca --target ./dist/service
accuknox-aspm-scanner scan --skip-upload --keep-results sca --target ./dist/application.jar
accuknox-aspm-scanner scan --skip-upload --keep-results sca --target ./package-lock.json
accuknox-aspm-scanner scan --skip-upload --keep-results sca --target ./dependencies.cdx.json
accuknox-aspm-scanner scan --skip-upload --keep-results sbom --target ./dist/service

# Upload results using existing ACCUKNOX_ENDPOINT/TOKEN/LABEL/TENANT settings.
accuknox-aspm-scanner scan --project-name payments sca --target ./dist/service --asset-name payment-service
```

`--target-type auto|directory|manifest|binary|archive|sbom` controls input detection.
`--target` and legacy `--command` are mutually exclusive. Use a directory to include
companion manifests/lockfiles while preserving relative paths. Standalone manifest
scans select only that file. No dependency installation or build execution occurs.
Existing CycloneDX and SPDX **JSON** SBOMs are supported; XML/tag-value are excluded.
For reproducible disconnected scans, populate `--cache-dir` first, then use
`--offline`. Container mode mounts the selected input read-only and maps input,
result and cache paths explicitly; it does not require a Docker socket mount.

Native Syft 1.42.3 downloads are verified against pinned SHA-256 checksums on Linux,
macOS and Windows. Trivy remains pinned to 0.69.3. `SYFT_IMAGE` and `SCAN_IMAGE`
override the corresponding container images.

Use `--output-dir` outside the target directory to retain `result.json`,
`sbom.json`, and `vulnerabilities.json`. Otherwise a temporary result directory is
used; `--keep-results` retains it. Operational failures retain diagnostics/results.
Exit codes for these new workflows are `0` success, `1` severity gate, `2`
operational/incomplete inventory failure. `--softfail` applies to severity gates.
Limited nonempty inventory can still match advisories; it does not establish that
all embedded dependencies were identified. Stripped binaries may have no usable
metadata and cannot be declared vulnerability-free.

### Mobile scanning from CI/CD

Full APK/IPA analysis runs on the backend's existing mobile services:

```sh
accuknox-aspm-scanner scan --project-name mobile-app mobile --target ./app.apk --asset-name android-app
accuknox-aspm-scanner scan --project-name mobile-app mobile --target ./app.apk --mode static_dynamic
accuknox-aspm-scanner scan --project-name mobile-app mobile --target ./app.ipa --mode static
accuknox-aspm-scanner scan --project-name mobile-app mobile --target ./app.apk --no-wait --idempotency-key build-123
accuknox-aspm-scanner scan --keep-results mobile --run-id RUN_UUID --output-dir ./mobile-results
```

Default static mode includes SBOM and dependency vulnerability matching. Dynamic
mode requires an Android analyzer; IPA supports static/SBOM modes. `--mode sbom`
uses the backend's mobile inventory and dependency pipeline. Mobile analysis cannot
use `--skip-upload`. Commands wait by default (`--timeout`, default 3600 seconds),
or return a run ID with `--no-wait`. Resume a wait/download with `--run-id`.
A timeout does not cancel the backend run. Backend capability checks report missing
services or an incompatible deployment before starting work.
