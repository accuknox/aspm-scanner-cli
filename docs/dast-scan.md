# DAST Scan

`accuknox-aspm-scanner scan dast` runs a dynamic scan against a live target. This guide covers
all four ways to run it: `--scan-type baseline`/`full`, `--scan-type api` for an
OpenAPI/Swagger/SOAP/GraphQL definition, the `--auth-*` convenience flags for a
browser-authenticated scan, and `--dast-plan` for full control via an automation plan.

DAST requires `--container-mode` (Docker) in every case above. Authenticated scans (`--auth-*` or
a plan with an `authentication` block) additionally need the headless Firefox/geckodriver bundled
in the scanner image — nothing extra to install, it's already there.

## Quick reference

Local run, no upload (swap in your own target/credentials):

```bash
# Unauthenticated — passive only (baseline)
accuknox-aspm-scanner scan --skip-upload --keep-results dast \
  --scan-type baseline --target https://example.com --options "-m 5" \
  --container-mode \
  --severity-threshold HIGH

# Unauthenticated — passive + active scan (full)
accuknox-aspm-scanner scan --skip-upload --keep-results dast \
  --scan-type full --target https://example.com --options "-m 5" \
  --container-mode \
  --severity-threshold HIGH

# Authenticated — browser-based login
accuknox-aspm-scanner scan --skip-upload --keep-results dast \
  --scan-type baseline --target https://example.com --options "-m 5" \
  --container-mode \
  --severity-threshold HIGH \
  --auth-url "https://example.com/login" \
  --auth-username "user@example.com" \
  --auth-password "your-password" \
  --auth-login-fallback-url "https://example.com/account" \
  --auth-logged-in-regex "user@example\.com"

# API scan against a Swagger/OpenAPI definition (openapi.json in current dir)
accuknox-aspm-scanner scan --skip-upload --keep-results dast \
  --scan-type api --target openapi.json --options "-f openapi -O https://example.com" \
  --container-mode \
  --severity-threshold HIGH

# Bring-your-own automation plan (plan.yaml in current dir)
accuknox-aspm-scanner scan --skip-upload --keep-results dast \
  --dast-plan ./plan.yaml \
  --container-mode \
  --severity-threshold HIGH
```

With AccuKnox upload — pass `--endpoint`/`--label`/`--token` explicitly, or `export` them once and
omit the flags (both work identically):

```bash
export ACCUKNOX_ENDPOINT=cspm.accuknox.com
export ACCUKNOX_LABEL=POC
export ACCUKNOX_TOKEN=abcd1234

accuknox-aspm-scanner scan dast \
  --scan-type baseline --target https://example.com --options "-m 5" \
  --container-mode \
  --auth-url "https://example.com/login" \
  --auth-username "user@example.com" \
  --auth-password "your-password" \
  --auth-login-fallback-url "https://example.com/account" \
  --auth-logged-in-regex "user@example\.com"
```

`--endpoint`/`--label`/`--token` are **top-level `scan` flags** — they go *before* `dast`, not
after. Everything else (`--scan-type`, `--target`, `--options`, `--dast-plan`, `--auth-*`, `--severity-threshold`,
`--container-mode`) goes *after* `dast`.

## 1. Unauthenticated scan (`--scan-type baseline|full`)

The scan runs inside the container against `--target`; `--options` passes extra scanner options.

```bash
accuknox-aspm-scanner scan --skip-upload --keep-results dast \
  --scan-type baseline --target https://example.com --options "-m 5" \
  --container-mode \
  --severity-threshold HIGH
```

- `baseline` = passive scan only (spider + passive rules). `full` adds an active scan.
- `--target <url>` is required. `--options "-m <minutes>"` bounds how long the spider runs (the
  default is 1 minute if omitted).
- Report options (`-J`/`-r`/`-w`/`-x`) are stripped and replaced — the CLI always forces JSON output
  to `results.json`, which `--severity-threshold` and upload both depend on.

## 2. API scan against an OpenAPI/Swagger/SOAP/GraphQL definition (`--scan-type api`)

The `api` scan type (unlike the other two) doesn't spider — it directly tests every operation the
definition describes.

```bash
accuknox-aspm-scanner scan dast \
  --scan-type api --target openapi.json --options "-f openapi -O https://example.com" \
  --container-mode
```

- `--target` — the definition itself: a local file (put it in your current directory, it's
  mounted into the container) or a URL. `openapi.json`, `soap`, and `graphql` are all valid.
- `--options "-f openapi|soap|graphql"` — the definition format.
- `--options "-O <url>"` — override host: the live site to actually test, when it differs from whatever
  `servers`/`host` the definition itself declares.
- `--options "--schema <url-or-file>"` — GraphQL schema location (GraphQL only).

Verified end-to-end against a local Juice Shop instance with a small hand-written OpenAPI
definition covering `/rest/products/search` and `/rest/user/whoami` — found a genuine HIGH-risk
SQL Injection alert on the `q` search parameter, correctly exiting 1 under
`--severity-threshold HIGH`.

## 3. Authenticated scan (`--auth-*`)

Use this when you just need username/password login without hand-writing YAML. Under the hood the
CLI builds an automation plan using **browser-based authentication**: a real headless
Firefox loads the login page and submits it, so this works for plain HTML forms *and* JS/SPA
logins (React/Angular apps, e.g. OWASP Juice Shop) — not just simple form posts.

```bash
accuknox-aspm-scanner scan dast \
  --scan-type baseline --target https://example.com --options "-m 5" \
  --container-mode \
  --auth-url "https://example.com/login" \
  --auth-username "user@example.com" \
  --auth-password "..." \
  --auth-login-fallback-url "https://example.com/account" \
  --auth-logged-in-regex "user@example\.com"
```

`--target` and `--options "-m ..."` still supply the target and spider duration; `--scan-type baseline`
vs. `full` still decides passive-only vs. +activeScan, same as the unauthenticated flow.

### Flags

| Flag | Required | Meaning |
|---|---|---|
| `--auth-url` | yes (with auth) | Login page URL, loaded in the headless browser |
| `--auth-username` | yes (with auth) | Username / email |
| `--auth-password` | yes (with auth) | Password |
| `--auth-logged-in-regex` | no | Regex matched against a response to confirm login succeeded |
| `--auth-logged-out-regex` | no | Regex matched against a response to confirm the session is unauthenticated |
| `--auth-login-fallback-url` | no | Post-login page the scanner polls to verify the session is still valid (e.g. a "whoami"/account endpoint). Without it, the indicator regexes are matched against every response instead of a dedicated poll. |

`--auth-url`/`--auth-username`/`--auth-password` are all-or-nothing. Session tracking (cookie or
an auth-style header, e.g. a JWT) is handled automatically for browser-based auth — there is
no separate "session header" flag to configure.

### Worked example: OWASP Juice Shop

This is the exact command verified against a local Juice Shop container
(`docker run -p 3000:3000 bkimminich/juice-shop`) with a freshly registered test user:

```bash
accuknox-aspm-scanner scan dast \
  --scan-type baseline --target http://host.docker.internal:3000 --options "-m 5" \
  --container-mode \
  --severity-threshold HIGH \
  --auth-url "http://host.docker.internal:3000/#/login" \
  --auth-username "tester@example.com" \
  --auth-password "Test1234!" \
  --auth-login-fallback-url "http://host.docker.internal:3000/rest/user/whoami" \
  --auth-logged-in-regex "tester@example\.com"
```

`host.docker.internal` resolves to the host machine from inside the scanner container on Docker
Desktop; swap it for your real target when scanning a deployed app.

### How to tell auth actually worked

A scan that "finds nothing" is ambiguous — did it authenticate and find nothing, or fail to log in
and scan an anonymous session? Two ways to check:

1. Run with `DEBUG=TRUE` and look for `Automation plan succeeded!` near the end of the scanner output.
   A verification failure (`loggedInRegex`/`loggedOutRegex`/poll not matching) surfaces as a job
   error there.
2. Check `results.json` for signs of an authenticated session — e.g. against Juice Shop, a real
   login produces an `Information Disclosure - JWT in Browser localStorage` alert, since a JWT
   only lands in local storage after a successful login.

You may also see `[Fatal Error] :1:1: Content is not allowed in prolog.` in the scanner output during
spidering — this is the scanner's own benign XML-parser noise on non-XML responses, not a scan failure.

## 4. Bring your own plan (`--dast-plan`)

Use this for authenticated scans that need more than `--auth-*` gives you — `spiderAjax`,
active-scan tuning, an auth method other than `browser`, multiple users, custom verification —
by supplying an automation plan (YAML) directly. Unauthenticated scans don't need this:
`--scan-type baseline|full|api` already covers them.

```bash
accuknox-aspm-scanner scan dast --dast-plan ./plan.yaml --container-mode
```

Start from [`docs/examples/dast-plan-template.yaml`](examples/dast-plan-template.yaml) — a
browser-authenticated context (spider + spiderAjax + passive scan), with `activeScan` commented
out to opt into deliberately.

- `--scan-type`/`--target` are not used in this mode — the plan's `env.contexts[].urls` supplies the target.
- Only the `report` job in your plan is overridden (pinned to `results.json`, `traditional-json`
  template) so `--severity-threshold` and upload keep working. Every other job runs as you wrote
  it.
- `--dast-plan` and `--auth-*` are mutually exclusive.

## Uploading results

`--endpoint`/`--label`/`--token` (top-level `scan` flags, before `dast`) can be passed on the
command line or left unset and picked up from `ACCUKNOX_ENDPOINT`/`ACCUKNOX_LABEL`/
`ACCUKNOX_TOKEN` in the environment — most CI setups just `export` these once rather than passing
them on every invocation. Use `--skip-upload --keep-results` to run locally without uploading and
keep `results.json` for inspection.
