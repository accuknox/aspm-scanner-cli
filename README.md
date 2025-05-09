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