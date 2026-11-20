# Pipeline command

`accuknox-aspm-scanner pipeline` runs several scans in one step, uploads them to AccuKnox as **one run**, and
(optionally) waits for the AccuKnox **quality gate** to decide whether the build passes.

Use it instead of chaining several `scan` commands plus `gate`: it picks one run id for every scan, tells the
gate exactly which scans have results to evaluate, and returns a single exit code.

## Quick start

```bash
export ACCUKNOX_ENDPOINT=cspm.accuknox.com
export ACCUKNOX_LABEL=my-label
export ACCUKNOX_TOKEN=<token>
export ACCUKNOX_GATE_TOKEN=<user token>     # only needed with --quality-gate, see "Tokens"

accuknox-aspm-scanner pipeline --scans sast,sca,secret,iac --quality-gate
```

Run it from the root of the repository you want to scan. Install the scanner tools first when running in
local mode (`accuknox-aspm-scanner tool install --type <sast|iac|secret|container|...>`), or add
`--container-mode` to run every scanner in a container instead.

## What it does

1. **Run** each scan in the order given by `--scans`. A scan that cannot run is recorded as broken; the others
   still run (unless `--fail-fast`).
2. **Upload** every result that was produced. Empty SBOMs and scans with no result (for example a clean secret
   scan) are skipped, and the gate is told only about the scans that were actually uploaded, so it never waits
   for something that will not arrive.
3. **Decide the build** (only with `--quality-gate`): poll AccuKnox for the verdict, print a per-scanner table
   and the breached thresholds, and exit accordingly.

## Choosing scans

`--scans` takes a comma-separated list (required). Duplicates are ignored.

| Scan | What it runs | Default arguments | Option to change them |
|---|---|---|---|
| `sast` | OpenGrep SAST | `scan .` | `--sast-command` |
| `sq-sast` | SonarQube SAST | *(none, required)* | `--sq-sast-command` |
| `sca` | Trivy dependency scan | `fs .` | `--sca-command` |
| `secret` | Secret scan | `filesystem .` | `--secret-command`, `--secret-engine trufflehog\|gitleaks` |
| `iac` | Checkov IaC scan | `-d .` | `--iac-command` |
| `sbom` | Container / filesystem SBOM | `filesystem .` | `--sbom-command` and the SBOM options below |

```bash
# Scan a subdirectory, and use gitleaks for secrets
accuknox-aspm-scanner pipeline --scans sast,secret \
  --sast-command "scan ./services/api" \
  --secret-command "filesystem ./services/api" --secret-engine gitleaks
```

## Common options

| Option | Purpose |
|---|---|
| `--endpoint`, `--label`, `--token`, `--tenant` | Upload settings. Default to `ACCUKNOX_ENDPOINT`, `ACCUKNOX_LABEL`, `ACCUKNOX_TOKEN`, `ACCUKNOX_TENANT`. |
| `--project-name` | Project name. **Required for the `sbom` scan.** |
| `--quality-gate` | Let the AccuKnox policy decide the build (also `ACCUKNOX_QUALITY_GATE=true`). |
| `--softfail` | Report findings / a policy failure without failing the build (also `SOFT_FAIL=TRUE`). |
| `--skip-upload` | Run the scans only; nothing is uploaded. Cannot be combined with `--quality-gate`. |
| `--keep-results` | Keep the result files (the directory is printed at the end). |
| `--container-mode` | Run every scanner in a container. |
| `--fail-fast` | Stop at the first scan that cannot run. |
| `--cli-id` | Run id (default `ACCUKNOX_CLI_ID`, else derived from the CI run). |
| `--repository` | `owner/name` that policy scopes match (default: detected from the repository URL). |

### Quality gate options

| Option | Default | Purpose |
|---|---|---|
| `--gate-timeout <seconds>` | `300` | How long to wait for the verdict. |
| `--gate-on-timeout fail\|pass` | `fail` | What to do if no verdict arrives in time. |
| `--gate-token` | `ACCUKNOX_GATE_TOKEN` | User token for the gate API. |
| `--gate-json-file <path>` | `ACCUKNOX_GATE_JSON_FILE` | Also write the gate response (JSON) to a file. |

### AI analysis (SAST)

`--ai-analysis` runs AI analysis on the scans that support it (today: `sast`). It is off by default; other scan
types ignore it. These options only work together with `--ai-analysis`:

- `--aiscan-severity HIGH,CRITICAL` – only analyze findings of these severities
- `--codeassure-config <path>` – model config (`codeassure.json`)
- `--context-graph-config <path>` – `context_graph.json`
- `--graph-no-joern` – use tree-sitter graphs without Joern

Install the AI SAST binaries first with `accuknox-aspm-scanner tool install --type codeassure`.

### SBOM options (`sbom` scan)

| Option | Purpose |
|---|---|
| `--sbom-format cyclonedx\|spdx` | SBOM standard (default `cyclonedx`). |
| `--sbom-author <name>` | Author recorded in the SBOM (default: CI actor or git identity). |
| `--sbom-version <n>` | Revision number written as the SBOM version. |
| `--sbom-vex <file>` | VEX file (OpenVEX, CycloneDX VEX or CSAF) to apply. Repeatable. |
| `--cert-in-check` | Fail unless the SBOM meets the CERT-In minimum data fields. |

`--project-name` is required for SBOM uploads.

## Exit codes

**With `--quality-gate`**

| Situation | Exit code |
|---|---|
| Gate passed, or passed with warnings | `0` |
| Gate failed (a `block` policy action) | `1` |
| A scan could not run, an upload failed, or no verdict (`--gate-on-timeout fail`) | `2` |

Findings no longer fail the individual scan steps: the policy decides. `--softfail` turns a policy failure
(`1`) into `0`, but never hides a scan that could not run or be evaluated. A SAST scanner exit code of `2`
(the scanner or its AI analysis failed) is always kept as a failure.

**Without `--quality-gate`** the scans simply run one after another and the exit code is the worst scanner
exit code (any scan that cannot run or upload gives `2`). `--softfail` forgives findings only.

## Tokens

Uploads use `ACCUKNOX_TOKEN`. The gate API identifies a *user*, which that token may not, so the pipeline
polls with `ACCUKNOX_GATE_TOKEN` (or `--gate-token`) and falls back to `ACCUKNOX_TOKEN`. Keep both as CI
secrets.

## Machine-readable result

After the verdict the gate response is printed as JSON on **stdout** (logs go to stderr), between
`----- quality gate response (json) -----` and `----- end quality gate response -----`. Use
`--gate-json-file` if an automation should not parse stdout.

## CI examples

**GitHub Actions**

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

**GitLab CI**

```yaml
accuknox:
  script:
    - accuknox-aspm-scanner pipeline --scans sast,sca,secret,iac --quality-gate
  variables:
    ACCUKNOX_ENDPOINT: cspm.accuknox.com
    ACCUKNOX_LABEL: my-label
    # ACCUKNOX_TOKEN and ACCUKNOX_GATE_TOKEN: set as masked CI/CD variables
```

**Local dry run (no upload, keep the results)**

```bash
accuknox-aspm-scanner pipeline --scans sast,iac --skip-upload --keep-results
```

**SBOM with CERT-In check**

```bash
accuknox-aspm-scanner pipeline --scans sbom --project-name my-app \
  --sbom-author "Platform Team" --cert-in-check
```

**SAST with AI analysis on high-severity findings**

```bash
accuknox-aspm-scanner pipeline --scans sast,sca --quality-gate \
  --ai-analysis --aiscan-severity HIGH,CRITICAL
```

## Troubleshooting

- **`Unknown scan(s)`** – check the spelling in `--scans`; valid names are `sast`, `sq-sast`, `sca`, `secret`,
  `iac`, `sbom`.
- **`--sq-sast-command is required`** – `sq-sast` has no default command.
- **`--quality-gate needs the results uploaded`** – remove `--skip-upload`.
- **`--aiscan-severity ... only apply with --ai-analysis`** – add `--ai-analysis`.
- **Gate times out on the first run** – AccuKnox downloads reference data the first time for a scan type;
  raise `--gate-timeout`.
- **Gate token rejected** – set `ACCUKNOX_GATE_TOKEN` to a user token.
- **Policy scope does not match** – set `ACCUKNOX_REPO_URL` / `ACCUKNOX_BRANCH` (or `--repository`) when the
  repository or branch cannot be detected from CI or git.

See also the [Quality Gates](../README.md#quality-gates) section of the README for running scans and `gate` as
separate steps.
