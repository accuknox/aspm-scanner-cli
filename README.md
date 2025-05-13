# AccuKnox ASPM Scanner

## Overview

The **AccuKnox ASPM Scanner** is a command-line tool designed to support a range of security testing methodologies, including:

* **SAST (Static Application Security Testing)**
* **DAST (Dynamic Application Security Testing)**
* **IaC (Infrastructure-as-Code) Scanning**
* **Secret Scanning**
* **Container Image Scanning**

## Prerequisites

Before using the **AccuKnox ASPM Scanner**, ensure the following tools are installed:

1. **Git**
2. **Docker**
3. **Python 3.10 or higher**

## Required Environment Variables

Set the following environment variables before running the scanner:

| **Variable**           | **Description**                                                 | **Required** | **Default Value** |
| ---------------------- | --------------------------------------------------------------- | ------------ | ----------------- |
| **ACCUKNOX_TENANT**   | The ID of the tenant associated with the CSPM panel              | Yes          | N/A               |
| **ACCUKNOX_ENDPOINT** | The URL of the CSPM panel to push scan results to                | Yes          | N/A               |
| **ACCUKNOX_LABEL**    | The label created in AccuKnox SaaS for associating scan results  | Yes          | N/A               |
| **ACCUKNOX_TOKEN**    | The token for authenticating with the CSPM panel                 | Yes          | N/A               |

## How It Works

**Error Handling**: The tool uses a `softfail` mode to ensure the scan continues even if vulnerabilities are found. This prevents the tool from exiting with a `0` status in case of issues.

### IaC Scanning 

1. Docker pulls the IAC image to execute the scan.
2. Based on the provided arguments (file or directory), the IAC Scan command is constructed.
3. IAC tool performs the scan and generates a result file in JSON format.
4. The result file is processed by appending metadata (repo URL, branch).
5. Results are uploaded to the AccuKnox endpoint.

Here’s a breakdown of the arguments:

| **Input**                | **Description**                                                                 | **Default Value**         |
|--------------------------|---------------------------------------------------------------------------------|---------------------------|
| **--file**               | Specify a file for scanning (e.g., ".tf" for Terraform). Cannot be used with directory input. | `""` (empty, optional)    |
| **--directory**          | Directory with infrastructure code and/or package manager files to scan         | `"."` (current directory)  |
| **--compact**            | Do not display code blocks in the output                                        | `False` (boolean)          |
| **--quiet**              | Display only failed checks                                                      | `False` (boolean)          |
| **--framework**      | Filter scans by specific frameworks, e.g., --framework terraform,kubernetes. For all frameworks, use all           | `"all"`  |
| **--repo-url**         | Git repository URL. If not provided, it is fetched automatically using Git CLI.                                                               | Fetched via Git CLI if not provided	                   |
| **--repo-branch**      | Git repository branch. If not provided, it is fetched automatically using Git CLI.	                                                             | Fetched via Git CLI if not provided	                    |

### SAST Scanning

The **SAST Scan** inspects your source code for potential security vulnerabilities. This scan is ideal for catching insecure coding patterns, hardcoded secrets, or misconfigurations early in the development cycle.

1. The tool pulls the Docker image.
2. It runs the scan against the local project directory by mounting it inside the container.
3. Environment variables like `REPOSITORY_URL` and `COMMIT_SHA` are injected into the container for traceability.
4. The results are saved to a `results.json` file.
5. These results are enriched with metadata and uploaded to the configured AccuKnox CSPM panel.

Here’s a breakdown of the arguments:

| **Input**       | **Description**                                      | **Default Value**         |
| --------------- | ---------------------------------------------------- | ------------------------- |
| `--repo-url`    | Git repository URL                                   | Auto-detected via Git CLI |
| `--commit-ref`  | Git reference/tag/branch for the scan                | Auto-detected via Git CLI |
| `--commit-sha`  | Specific Git commit SHA to identify the scan version | Auto-detected via Git CLI |
| `--pipeline-id` | Optional pipeline ID to correlate with CI/CD runs    | `""`                      |
| `--job-url`     | Optional URL to the job in CI/CD                     | `""`                      |

> 📝 **Note:** If scanning against a Git-cloned directory, the `repo-url`, `commit-ref`, and `commit-sha` arguments are optional. They will be automatically detected using the local Git configuration.

#### Example Command

```bash
accuknox-aspm-scanner scan sast --softfail
```

### SonarQube SAST Scanning

The **SonarQube SAST Scan** leverages **SonarQube** to analyze your source code for security vulnerabilities. This scan is specifically tailored to work with **SonarQube-based SAST** and integrates seamlessly with **AccuKnox** for advanced security posture management.

1. The tool runs a **SonarQube scan** using the official `sonarsource/sonar-scanner-cli` Docker image.
2. If the SonarQube scan is skipped (`skip_sonar_scan=True`), the tool skip the scanning and fetches results from the SonarQube API.
3. The results from the scan are processed and uploaded to the configured AccuKnox panel for further analysis.

Here’s a breakdown of the arguments:

| **Input**             | **Description**                                                                | **Default Value**             |
| --------------------- | ------------------------------------------------------------------------------ | ----------------------------- |
| `--skip-sonar-scan`   | Flag to skip the SonarQube scan (defaults to `True` if scanning only AccuKnox) | `False`                        |
| `--sonar-project-key` | SonarQube project key to identify the project being scanned                    | `None` (Required)             |
| `--sonar-token`       | The SonarQube token for authenticating API requests                            | `None` (Required)             |
| `--sonar-host-url`    | The URL of the SonarQube instance                                              | `None` (Required)             |
| `--sonar-org-id`      | The organization ID in SonarQube (optional)                                    | `None` (Optional)             |
| `--repo-url`          | Git repository URL                                                             | Auto-detected if not provided |
| `--branch`            | Git branch to scan                                                             | Auto-detected if not provided |
| `--commit-sha`        | Commit SHA for the scan                                                        | Auto-detected if not provided |
| `--pipeline-url`      | Optional URL to the pipeline where the scan is triggered                                | `""`                          |

> 📝 **Note:** The `repo-url`, `branch`, and `commit-sha` are optional if scanning against a Git-cloned directory. They will be automatically detected using the local Git configuration.

#### Example Command

```bash
accuknox-aspm-scanner scan sq-sast --sonar-project-key PROJ_KEY --sonar-host-url URL --sonar-token TOKEN --skip-sonar-scan
```