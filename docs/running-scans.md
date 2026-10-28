# Running scans: individually and together

Every scan runs in two modes:

- **Local mode** (default): uses scanner binaries installed on the machine. Works on Linux, macOS and Windows. Install once with `tool install`.
- **Container mode** (`--container-mode`): runs the scanner in Docker. Needs Docker running; nothing to install.

All commands below use `--skip-upload --keep-results` (local files only). To upload to AccuKnox, drop `--skip-upload` and set the credentials:

```bash
export ACCUKNOX_ENDPOINT=cspm.dev.accuknox.com   # your env
export ACCUKNOX_LABEL=cli
export ACCUKNOX_TOKEN=<token>
```

Add `--softfail` to any scan to exit `0` even when findings are present (otherwise findings exit `1`).

## 0. One-time setup (local mode only)

```bash
accuknox-aspm-scanner tool install --type iac
accuknox-aspm-scanner tool install --type sast
accuknox-aspm-scanner tool install --type secret
accuknox-aspm-scanner tool install --type container   # SCA, container, SBOM
```

Other types: `gitleaks`, `sq-sast`, `dast`, `codeassure` (AI SAST analysis). Not every type is available on every OS; the installer says so if not.

## 1. Individual scans

Run from the root of the code you want to scan. Result files land in the current directory.

| Scan | Local mode | Container mode | Result file |
|---|---|---|---|
| IaC | `scan --skip-upload --keep-results iac --command "-d ."` | same + `--container-mode` | `results_json.json` |
| SAST | `scan --skip-upload --keep-results sast --command "scan ."` | same + `--container-mode` | `results.json` |
| Secret | `scan --skip-upload --keep-results secret --command "filesystem ."` | same + `--container-mode` | `results.jsonl` |
| SCA | `scan --skip-upload --keep-results sca --command "fs ."` | same + `--container-mode` | `results.json` |
| Container (vulnerabilities) | `scan --skip-upload --keep-results container --command "image alpine:3.18"` | same + `--container-mode` | `results.json` |
| ML model | `scan --skip-upload --keep-results ml-scan --command "scan -p . -r json"` | same + `--container-mode` | `results.json` |
| API discovery | `scan --skip-upload --keep-results api-discovery --command "-path . -output results.json"` | same + `--container-mode` | `results.json` |
| DAST | `scan --skip-upload --keep-results dast --command "zap-baseline.py -t http://example.com/ -I"` | same + `--container-mode` | `results.json` |
| SonarQube SAST | `scan --skip-upload --keep-results sq-sast --command "-Dsonar.projectKey=<KEY> -Dsonar.host.url=<URL> -Dsonar.token=<TOKEN> -Dsonar.organization=<ORG>"` | same + `--container-mode` | `results.json` |

Prefix every row with `accuknox-aspm-scanner`. Example, both modes:

```bash
# local
accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ."
# container
accuknox-aspm-scanner scan --skip-upload --keep-results sast --command "scan ." --container-mode
```

Useful extras: `--severity HIGH,CRITICAL` (iac, sast, sca, sq-sast: which severities fail the scan), `--repo-url`, `--repo-branch`/`--commit-ref` (metadata, auto-detected from git).

Notes:
- SAST on Windows is slow (about 5 minutes for ~1000 rules) but correct. Wait for it; the default timeout is 1 hour (`SCAN_TIMEOUT_SECONDS` to change).
- `container --command "image <name>"` needs the image to be pullable by the scanner. In container mode, Docker also mounts its socket for image scans.

## 2. SBOM (CycloneDX)

SBOM is a `container` scan with `--generate-sbom`. The first word of `--command` picks the type:

| What | Command value | `project_classifier` |
|---|---|---|
| Container image | `image nginx:latest` | `container` |
| Source tree / filesystem | `filesystem .` (or `fs .`) | `application` |

`--project-name` (or `ACCUKNOX_PROJECT_NAME`) is **required** to upload an SBOM. The project is created automatically if it does not exist yet; you no longer create it in the dashboard first.

```bash
# local mode
accuknox-aspm-scanner scan --project-name my-app container --command "filesystem ." --generate-sbom
accuknox-aspm-scanner scan --project-name my-app container --command "image nginx:latest" --generate-sbom

# container mode
accuknox-aspm-scanner scan --project-name my-app container --command "filesystem ." --generate-sbom --container-mode
accuknox-aspm-scanner scan --project-name my-app container --command "image nginx:latest" --generate-sbom --container-mode

# local file only, no upload (no project name needed)
accuknox-aspm-scanner scan --skip-upload --keep-results container --command "filesystem ." --generate-sbom
```

Check the classifier: `python -c "import json;print(json.load(open('results.json'))['project_classifier'])"`.

## 3. Running everything together

The CLI runs one scan per invocation. Several scans write the same `results.json`, so give each scan its own working directory (or move the file after each run), otherwise they overwrite each other.

### Linux / macOS / WSL (bash)

```bash
#!/bin/bash
# usage: ./run-all.sh [--container-mode]
MODE="$1"                      # empty = local mode
SRC="$(pwd)"
OUT="$SRC/scan-output"; mkdir -p "$OUT"
FLAGS="--skip-upload --keep-results --softfail"   # remove --skip-upload to upload

run() {  # run <name> <scan args...>
  name=$1; shift
  d="$OUT/$name"; mkdir -p "$d"; cd "$SRC"
  accuknox-aspm-scanner scan $FLAGS "$@" $MODE
  mv results*.json* "$d/" 2>/dev/null
}

run iac       iac       --command "-d ."
run sast      sast      --command "scan ."
run secret    secret    --command "filesystem ."
run sca       sca       --command "fs ."
run sbom-fs   --project-name my-app container --command "filesystem ." --generate-sbom
run sbom-img  --project-name my-app container --command "image nginx:latest" --generate-sbom
echo "results in $OUT"
```

### Windows (PowerShell)

```powershell
param([string]$Mode = "")        # pass --container-mode for container mode
$src = (Get-Location).Path; $out = "$src\scan-output"; New-Item -ItemType Directory -Force $out | Out-Null
$flags = @("--skip-upload","--keep-results","--softfail")   # remove --skip-upload to upload

function Run($name, [string[]]$scanArgs) {
  Set-Location $src
  $extra = @(); if ($Mode) { $extra += $Mode }
  accuknox-aspm-scanner scan @flags @scanArgs @extra
  New-Item -ItemType Directory -Force "$out\$name" | Out-Null
  Move-Item "results*.json*" "$out\$name" -Force -ErrorAction SilentlyContinue
}

Run "iac"      @("iac","--command","-d .")
Run "sast"     @("sast","--command","scan .")
Run "secret"   @("secret","--command","filesystem .")
Run "sca"      @("sca","--command","fs .")
Run "sbom-fs"  @("--project-name","my-app","container","--command","filesystem .","--generate-sbom")
```

Run `./run-all.sh` for local mode and `./run-all.sh --container-mode` for container mode.

## 4. PR decoration (`decorate-pr`)

Posts the findings as a PR review. It only acts on a pull-request build (GitHub Actions `pull_request`, plus GitLab, Bitbucket, Azure DevOps); on any other run it logs "Not a pull/merge request build" and exits `0`.

```bash
# after the scans above, in the PR job
accuknox-aspm-scanner decorate-pr \
  --result-file scan-output/sast/results.json,scan-output/iac/results_json.json,scan-output/sca/results.json \
  --scan-type sast,iac,sca \
  --mode advisory            # or: --mode blocking --max-critical 0 --max-high 0

# preview only (no token, no network), still needs a PR environment to render
accuknox-aspm-scanner decorate-pr --result-file results.json --scan-type sast --dry-run
```

`--scan-type` values: `sast`, `sq-sast`, `iac`, `sca`, `secret`. Optional AI remediation: `--llm-api-key`. Full reference: [pr-decorator.md](pr-decorator.md).

## 5. Quality gate (`gate`)

Stamps scans with a shared run id, then fails the pipeline if the AccuKnox gate policy is breached. See "CI/CD Quality Gate" in the [README](../README.md).

```bash
export ACCUKNOX_CLI_ID=$(python -c "import uuid;print(uuid.uuid4())")
accuknox-aspm-scanner scan --repository org/repo --branch main --commit-sha "$(git rev-parse HEAD)" sast --command "scan ."
accuknox-aspm-scanner gate --scanner-prefixes SG
```

## 6. Troubleshooting

- `Tool not found. Please run scanner tool install --type X`: install the local tool, or add `--container-mode`.
- Container mode fails to start: Docker is not running (on WSL, start Docker Desktop or the Docker service).
- Nothing uploaded for secrets: no secrets found, so the upload is skipped by design.
- Scan "exited 1": findings at or above the `--severity` threshold. Use `--softfail` to keep going.
