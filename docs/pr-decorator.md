# PR Decorator

`accuknox-aspm-scanner decorate-pr` posts scan findings as a real GitHub PR
review — one summary comment (severity table + quality gate) plus inline
comments on the exact lines — instead of a wall of text in the Actions log.
Run it as a step right after a scan, in a `pull_request` job.

On anything that isn't a GitHub Actions `pull_request` build (a plain push,
another CI, a merge_group run, ...) it logs and exits `0` — safe to add to a
job that also runs on other triggers, nothing to gate it with `if:` yourself.

## Command

```bash
accuknox-aspm-scanner decorate-pr \
  --result-file <path>[,<path>...] \
  [--scan-type <type>[,<type>...]] \
  [--changed-files <path>[,<path>...]] \
  [--mode advisory|blocking] \
  [--max-critical N] [--max-high N] [--max-medium N] [--max-low N] \
  [--github-token <token>] \
  [--llm-api-key <key>] [--llm-model <model>] [--llm-base-url <url>] \
  [--dry-run]
```

| Flag | Default | What it does |
|---|---|---|
| `--result-file` | *(required)* | Scan result JSON, or a comma-separated list (one per scan type). |
| `--scan-type` | filename-sniffed | Comma-separated scan type per `--result-file` entry, same order. Allowed: `sast`, `sq-sast`, `iac`, `sca`, `secret`. Explicit and recommended — this CLI's own output filenames (`results.json`, `results_json.json`, `results.jsonl`) don't self-identify the way AccuKnox-labeled `<label>-<TYPE>-*.json` files do. |
| `--changed-files` | auto-computed | Comma-separated files to scope findings to. If omitted, computed from `git diff` between the PR's base and head SHA (read from `GITHUB_EVENT_PATH`). |
| `--mode` | `advisory` | `advisory` = comment only. `blocking` = `REQUEST_CHANGES` when a threshold below is exceeded. |
| `--max-critical` / `--max-high` | `0` / `0` | Quality gate: zero-tolerance by default. |
| `--max-medium` / `--max-low` | unlimited | Quality gate, optional. |
| `--github-token` | `$GITHUB_TOKEN` | Needs `pull-requests: write`. |
| `--llm-api-key` | `$LLM_API_KEY` / `$OPENROUTER_API_KEY` | Optional. Set to have an LLM generate a remediation suggestion for SAST findings with no native fix (~90% of rules). **Unset = that step is skipped entirely — no LLM call, no cost, findings post as-is.** SAST-only; ignored for iac/sca/secret. |
| `--llm-model` | `openai/gpt-4o-mini` | Only used if `--llm-api-key` is set. **Set this explicitly unless `--llm-base-url` is also left unset** — the default is OpenRouter's own model naming, meaningless against any other endpoint. |
| `--llm-base-url` | OpenRouter's endpoint | Any OpenAI-compatible chat-completions endpoint (OpenAI, Azure OpenAI, a self-hosted vLLM/Ollama server, Groq, Together, ...). **Set this explicitly for any key that isn't an OpenRouter key.** Leaving it unset sends `--llm-api-key` to OpenRouter's endpoint — a native OpenAI/Azure/self-hosted key sent there fails auth silently (a warning in the log, no crash, remediation just never shows up), not an obvious error. |
| `--dry-run` | off | Print what would be posted (summary body + inline comment payloads), no API calls, no token required. |

Exit code: `0` on success or a clean not-a-PR/not-yet-implemented-provider
skip. `1` if a real post was attempted with no token available.

## Quick reference

```bash
# SAST only, advisory
accuknox-aspm-scanner decorate-pr \
  --result-file results.json --scan-type sast \
  --mode advisory --max-critical 0 --max-high 0

# Combined scan (sast + iac + sca in one PR run), blocking on HIGH+
accuknox-aspm-scanner decorate-pr \
  --result-file results.json,results_json.json,sca-results.json \
  --scan-type sast,iac,sca \
  --mode blocking --max-critical 0 --max-high 0

# Secrets (TruffleHog, .jsonl - engine/format auto-detected from extension)
accuknox-aspm-scanner decorate-pr \
  --result-file results.jsonl --scan-type secret

# With AI remediation via OpenRouter (SAST only; omit --llm-api-key entirely to skip this step)
accuknox-aspm-scanner decorate-pr \
  --result-file results.json --scan-type sast \
  --llm-api-key "$OPENROUTER_API_KEY"

# With AI remediation via a non-OpenRouter provider - base-url/model required, not optional
accuknox-aspm-scanner decorate-pr \
  --result-file results.json --scan-type sast \
  --llm-api-key "$OPENAI_API_KEY" \
  --llm-base-url "https://api.openai.com/v1/chat/completions" \
  --llm-model "gpt-4o-mini"

# Preview only, no token needed, no network call
accuknox-aspm-scanner decorate-pr \
  --result-file results.json --scan-type sast --dry-run
```

## Wiring it into a GitHub Action for testing

`decorate-pr` needs to run after the scan step, in a `pull_request` job with
`pull-requests: write`. It reads PR context (number, base/head SHA) straight
off `GITHUB_EVENT_PATH` — nothing extra to pass beyond `GITHUB_TOKEN`.

```yaml
name: AccuKnox PR Decorator (test build)

on:
  pull_request:
    branches: [main]

permissions:
  pull-requests: write

jobs:
  scan-and-decorate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # decorate-pr needs the base commit for git diff

      # Swap this for however the test build's binary gets onto the runner -
      # a cross-workflow artifact download, or a binary committed straight
      # into this action's repo for the quickest test loop.
      - name: Install accuknox-aspm-scanner (test build)
        run: |
          chmod +x ./accuknox-aspm-scanner
          echo "$PWD" >> "$GITHUB_PATH"

      - name: Run SAST scan
        run: |
          accuknox-aspm-scanner scan --skip-upload --keep-results sast \
            --command "scan ."

      - name: Decorate PR with findings
        run: |
          accuknox-aspm-scanner decorate-pr \
            --result-file results.json --scan-type sast \
            --mode advisory --max-critical 0 --max-high 0
        env:
          GITHUB_TOKEN: ${{ github.token }}
```

Notes for the test loop:
- `GITHUB_EVENT_NAME`, `GITHUB_EVENT_PATH`, `GITHUB_REPOSITORY`, `GITHUB_SHA`
  are already set by Actions on every run — nothing to configure for PR
  detection itself.
- Start with `--dry-run` added to the last step to see the exact summary +
  inline comment payloads in the Actions log before it ever calls the GitHub
  API for real.
- `results.json` from `scan sast` is the same file `--result-file` /
  `--scan-type sast` above expects — no conversion step needed.
