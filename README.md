# AccuKnox ASPM Scanner CLI

![AccuKnox Logo](https://accuknox.com/wp-content/uploads/accuknox-logo-2.png)

**`accuknox-aspm-scanner`** is a unified command-line interface for running application security scans (IaC, SAST, Secret, Container, and DAST) as part of your CI/CD or developer workflow.  
It integrates with the **AccuKnox ASPM Platform** but can also operate **completely standalone** — ideal for on-premise or air-gapped environments.

---

## ✨ Features

- 🚀 One CLI for all security scan types: IaC, SAST, SonarQube SAST, Secret, Container, and DAST  
- 🔄 Direct execution using containerized or local tools  
- 🧩 Easy integration with CI/CD pipelines and pre-commit hooks  
- 🔐 Push results to AccuKnox ASPM Platform (optional)  
- 🧰 Fully offline/on-premise mode supported  
- 🧵 Environment variable and argument-based configuration  
- 🧾 Debug logging with full trace support

---

## 🛠️ Installation

### 1. From PyPI (Cloud or Connected Environment)

```bash
pip install https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.14.0/accuknox_aspm_scanner-0.14.0-py3-none-any.whl
````

### 2. From Precompiled Package (On-Prem Setup)

For restricted environments, you can install the precompiled `.deb.gz` package provided by AccuKnox:

![Releases](https://github.com/accuknox/aspm-scanner-cli/releases)
```bash
sudo dpkg -i accuknox-aspm-scanner_<version>.deb
```

---

## ⚙️ Environment Variables

The following variables are supported for configuration (accuknox vars are optional if `--skip-upload` is used):

| Variable            | Description                                                                            |
| ------------------- | -------------------------------------------------------------------------------------- |
| `ACCUKNOX_ENDPOINT` | URL of the AccuKnox Control Plane API endpoint                                         |
| `ACCUKNOX_LABEL`    | Label or project name to associate scan results                                        |
| `ACCUKNOX_TOKEN`    | Authentication token for the AccuKnox platform                                         |
| `ASPM_DEBUG`        | Set to `TRUE` to enable verbose trace output                                           |
| `SCAN_IMAGE`        | Override internal Docker images for on-prem scanners (e.g., `myregistry/accuknox-iac:latest`) |
| `KEEP_RESULTS`      | Set to `TRUE` to keep scan results file after completion                               |

> 💡 Use `--skip-upload` to disable result upload to the AccuKnox platform — useful for local testing or isolated environments.

---

## 🧩 Commands Overview

### 🔧 Tool Management

#### Install or Update Tools

```bash
accuknox-aspm-scanner tool install --all
```

Or install/update specific tools:

```bash
accuknox-aspm-scanner tool install --type iac
```

Supported tool types:

* `sast` – Static Code Analysis
* `sq-sast` – Static Analysis via SonarQube
* `secret` – Secret Detection
* `iac` – IaC Static Code Analysis
* `container` – Container Image Scanning
* `dast` – Dynamic Analysis

This installs the CLI into:

```
~/.local/bin/accuknox/
```

---

## 🔍 Scan Workflows

Each scan supports `--command`, which passes arguments **directly to the underlying scanner**.

### 🏗️ Infrastructure as Code (IaC) Scan

```bash
accuknox-aspm-scanner scan iac --command "-d ."
```

### 💻 Static Application Security Testing (SAST)

```bash
accuknox-aspm-scanner scan sast --command "scan ."
```

### 🔒 Secret Scanning

```bash
accuknox-aspm-scanner scan secret --command "git file://." --container-mode
```

### 🐳 Container Image Scanning

Scan a container image for vulnerabilities:

```bash
accuknox-aspm-scanner scan container --command "image nginx:latest"
```

#### Generate Software Bill of Materials (SBOM)

Instead of scanning for vulnerabilities, you can generate an SBOM (Software Bill of Materials) in CycloneDX format:

```bash
accuknox-aspm-scanner scan \
  --project-name "my-project" \
  container \
  --command "image nginx:latest" \
  --generate-sbom
```

**What is SBOM?**  
An SBOM is a complete inventory of all software components, libraries, and dependencies in your container image. It helps you:
- Track all components and their versions
- Understand your software supply chain
- Meet compliance requirements
- Identify affected components when vulnerabilities are disclosed

**When to use `--generate-sbom`:**
- When you need a complete inventory of all dependencies in your container
- For compliance and supply chain security requirements
- To track component versions across your container images

### 🌐 Dynamic Application Security Testing (DAST)

```bash
accuknox-aspm-scanner scan dast --command ""zap-baseline.py -t http://example.com/ -I"
```

### 🧠 SonarQube SAST Scan

```bash
accuknox-aspm-scanner scan sq-sast --command "-Dsonar.projectKey='<PROJECT KEY>' -Dsonar.host.url=<HOST URL> -Dsonar.token=<TOKEN> -Dsonar.organization=<ORG ID>"
```

---

## 🔁 Common Options

| Flag                           | Description                             |
| ------------------------------ | --------------------------------------- |
| `--endpoint`                   | Control Plane URL (overrides env var)   |
| `--label`                      | Label or project name                   |
| `--token`                      | Authentication token                    |
| `--project-name`               | Project name (required for SBOM uploads) |
| `--skip-upload`                | Skip uploading results to Control Plane |
| `--softfail`                   | Do not break CI/CD pipeline on findings |
| `--container-mode`             | Run scanner inside a container          |
| `--keep-results`               | Keep the scan results JSON file after completion (not deleted) |
| `--generate-sbom`              | Generate SBOM instead of vulnerability scan (container scans only) |

#### About `--keep-results`

By default, the scan results JSON file (`results.json`) is automatically deleted after the scan completes (unless upload fails). Use `--keep-results` to preserve the file for later review or analysis.

**When to use `--keep-results`:**
- When you need to review scan results locally
- For debugging and troubleshooting
- When integrating with custom analysis tools
- For audit and compliance record-keeping

**Example:**
```bash
accuknox-aspm-scanner scan container \
  --command "image nginx:latest" \
  --keep-results
```

The results file will be saved as `results.json` in the current directory.

#### About `--generate-sbom`

The `--generate-sbom` flag is available for container scans. It generates a Software Bill of Materials (SBOM) in CycloneDX JSON format instead of running a vulnerability scan.

**When to use `--generate-sbom`:**
- When you need a complete inventory of all dependencies
- For supply chain security and compliance
- To track component versions across container images
- For integration with SBOM analysis tools

**Example:**
```bash
accuknox-aspm-scanner scan \
  --project-name "my-application" \
  container \
  --command "image nginx:latest" \
  --generate-sbom \
  --keep-results
```

The SBOM will be saved as `results.json` in CycloneDX format. Use `--project-name` to tag the SBOM with your project identifier.

---

## 🧩 Example: Full End-to-End Run

```bash
ACCUKNOX_ENDPOINT=cspm.accuknox.com \
ACCUKNOX_LABEL=POC \
ACCUKNOX_TOKEN=abcd1234 \
accuknox-aspm-scanner scan sast \
  --command "scan ." \
  --softfail
```

---

## 🧱 Pre-Commit Integration

You can easily integrate **AccuKnox Secret Scan** into your development workflow using the [`pre-commit`](https://pre-commit.com) framework.

```bash
pip install pre-commit && accuknox-aspm-scanner pre-commit install
```

This automatically installs a `pre-commit` hook at:

```
.git/hooks/pre-commit
```

---

## 🧩 On-Premise & Air-Gapped Setup

In a fully offline/on-premise environment:

1. **Install** the precompiled `.deb.gz` or tarball
2. **Disable** container mode if installed natively
    3. For container mode **Set** `SCAN_IMAGE` to use internal registry images

Example:

```bash
export SCAN_IMAGE=registry.local/semgrep:latest
accuknox-aspm-scanner scan iac --command "-d ." --container-mode
```

---

## 🧪 Debugging

Enable verbose debug mode:

```bash
DEBUG=TRUE accuknox-aspm-scanner scan iac --command "-d ."
```

---

## 🔧 Troubleshooting

### GLIBC Version Compatibility Issue

If you encounter an error like:
```
Failed to load Python shared library: version `GLIBC_2.38' not found
```

This means the binary was built on a system with a newer GLIBC version than your system supports.

**Solutions:**

1. **Use the Python wheel package instead** (recommended):
   ```bash
   pip install https://github.com/accuknox/aspm-scanner-cli/releases/download/v<version>/accuknox_aspm_scanner-<version>-py3-none-any.whl
   ```

2. **Build the binary locally using Docker** (for maximum compatibility):
   ```bash
   # Build using the Dockerfile.build (uses Ubuntu 20.04 for max compatibility)
   docker build -f Dockerfile.build -t aspm-scanner-builder .
   docker create --name builder aspm-scanner-builder
   docker cp builder:/build/dist/accuknox-aspm-scanner ./dist/accuknox-aspm-scanner
   docker rm builder
   chmod +x ./dist/accuknox-aspm-scanner
   ```

3. **Build the binary locally on your system**:
   ```bash
   # Install dependencies
   sudo apt-get update
   sudo apt-get install -y python3.10 python3-pip python3-venv
   
   # Install pipenv
   pip3 install pipenv
   
   # Install project dependencies
   pipenv install
   pipenv run pip install pyinstaller
   
   # Build the binary
   pipenv run pyinstaller accuknox-aspm-scanner.spec
   
   # The binary will be in dist/accuknox-aspm-scanner
   ```

**Note:** Future releases are built using Docker with Ubuntu 20.04 (GLIBC 2.31) for maximum compatibility across Linux distributions. Binaries built on older systems work on newer systems (forward compatible).

---