# accuknox-aspm-scanner: standalone binaries

Single-file executables (PyInstaller, no Python needed on the target). Binaries are **not committed to git**:
they are built with `packaging/build-binaries.sh` into `dist/release/` (git-ignored) and attached to a release.

| Platform | File | Notes |
|---|---|---|
| Linux x86_64 | `accuknox-aspm-scanner-linux-amd64` | needs glibc >= 2.31 (Debian 11+, Ubuntu 20.04+, RHEL 9, Amazon Linux 2023) |
| Linux arm64 | `accuknox-aspm-scanner-linux-arm64` | same glibc floor |
| macOS Apple Silicon | `accuknox-aspm-scanner-darwin-arm64` | unsigned, see Gatekeeper below |

Windows and macOS Intel are not built by this script (the CI release workflow covers Windows).
The file names match the GitHub release assets in `.github/workflows/release.yml`.

## Install

```bash
# 1. download the file for your platform (and SHA256SUMS) from the release, then verify
shasum -a 256 -c SHA256SUMS --ignore-missing        # on Linux: sha256sum -c SHA256SUMS --ignore-missing

# 2. install
chmod +x accuknox-aspm-scanner-linux-amd64
sudo mv accuknox-aspm-scanner-linux-amd64 /usr/local/bin/accuknox-aspm-scanner

# 3. check
accuknox-aspm-scanner --version
```

macOS Gatekeeper: a binary downloaded through a browser carries a quarantine flag. Remove it once:
`xattr -d com.apple.quarantine accuknox-aspm-scanner-darwin-arm64`.

## Use

Configure the upload target once (or pass `--endpoint --label --token`):

```bash
export ACCUKNOX_ENDPOINT=cspm.accuknox.com
export ACCUKNOX_LABEL=<label>
export ACCUKNOX_TOKEN=<access token>
```

Single scan (see `README.md` > Scan Reference for every scan type):

```bash
accuknox-aspm-scanner scan sast --command "scan ."
accuknox-aspm-scanner scan secret --command "filesystem ."
```

CI pipeline with the quality gate (this build includes `pipeline` and `gate`):

```bash
export ACCUKNOX_GATE_TOKEN=<user token>      # the gate poll API needs a user token, not the access token
accuknox-aspm-scanner pipeline --scans sast,sca,secret,iac,sbom --quality-gate
# exit codes: 0 passed/warning, 1 policy failure, 2 scan not evaluable or timeout
```

The binary does not embed the scanners (opengrep, trivy, checkov, ...). Install them once with
`accuknox-aspm-scanner tool install --all` (placed in `~/.local/bin/accuknox/`), or use Docker with
`--container-mode`. See `README.md` > Tool Management.

## Build

Needs `uv` (macOS build) and Docker (Linux builds). Run from the repo root:

```bash
packaging/build-binaries.sh                 # macos-arm64 + linux-amd64 + linux-arm64
packaging/build-binaries.sh linux-amd64     # just one target
```

- macOS arm64 builds natively and must run on an Apple Silicon Mac.
- Linux builds run in `python:3.10-bullseye` (glibc 2.31). The script fails if the binary needs a newer glibc,
  and smoke-tests `--help` in the container. linux-amd64 on an Apple Silicon Mac runs under emulation (slow, a few minutes).
- Output in `dist/release/`: the three binaries, `SHA256SUMS`, `BUILD-INFO.txt` (version, commit, time).
- The version comes from `setup.cfg`. Bump it before building a release.

## Release checklist

1. Merge the code to release, bump `version` in `setup.cfg`, tag `vX.Y.Z`.
2. `packaging/build-binaries.sh` on a clean checkout of that tag.
3. Attach everything in `dist/release/` to the GitHub release for the tag (the CI workflow publishes the
   same asset names, so a manual upload replaces or complements it).
4. Update the download URLs in `README.md` and `aspm_cli/tool/download.py` if they point at an older tag.
