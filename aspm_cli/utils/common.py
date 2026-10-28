import os
import sys
import requests
import urllib3
# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import logging
from colorama import Fore

from aspm_cli.utils.logger import Logger
from aspm_cli.utils.spinner import Spinner

# Moved from original main.py
ALLOWED_SCAN_TYPES = [
    "iac",
    "sq-sast",
    "secret",
    "container",
    "sast",
    "dast",
    "sca",
    "ml-scan",
    "api-discovery",
]

# Artifact data_type prefixes the CI/CD quality gate can evaluate. Must stay in
# sync with the backend's PREFIX_TO_BUCKET (cicd/buckets.py). Only uploads whose
# prefix is in this set are stamped with the gate correlation params; every other
# prefix (e.g. SBOM, MLC, API, ZAP) uploads ungated as before.
GATE_SUPPORTED_PREFIXES = {
    "SG",          # sast
    "SQ",          # sq-sast
    "TR",          # sca / container (vuln)
    "IAC",         # iac
    "TruffleHog",  # secret (trufflehog, default)
    "DS",          # secret --engine gitleaks
}

def _build_endpoint_url(endpoint, api_path):
    """
    Build the full URL for API requests.
    If endpoint already includes protocol (http:// or https://), use it as-is.
    Otherwise, prepend https:// for production endpoints.
    """
    if endpoint.startswith(("http://", "https://")):
        return f"{endpoint}{api_path}"
    return f"https://{endpoint}{api_path}"

def clean_env_vars():
    """Removes surrounding quotes from all environment variables."""
    for key, value in os.environ.items():
        if value and (value.startswith(("'", '"')) and value.endswith(("'", '"'))):
            os.environ[key] = value[1:-1]

def print_banner():
    try:
        banner = r"""
        ┏━┓┏━╸┏━╸╻ ╻╻┏ ┏┓╻┏━┓╻ ╻ ┏━┓┏━┓┏━┓┏┳┓ ┏━┓┏━╸┏━┓┏┓╻┏┓╻┏━╸┏━┓
        ┣━┫┃  ┃  ┃ ┃┣┻┓┃┗┫┃ ┃┏╋┛ ┣━┫┗━┓┣━┛┃┃┃ ┗━┓┃  ┣━┫┃┗┫┃┗┫┣╸ ┣┳┛
        ╹ ╹┗━╸┗━╸┗━┛╹ ╹╹ ╹┗━┛╹ ╹ ╹ ╹┗━┛╹  ╹ ╹ ┗━┛┗━╸╹ ╹╹ ╹╹ ╹┗━╸╹┗╸
        """
        print(Fore.BLUE + banner)
    except:
        # Skipping if there are any issues with Unicode chars
        print(Fore.BLUE + "ACCUKNOX ASPM SCANNER")

def upload_results(file_path, endpoint, label, token, tenant_id, data_type, keep_file=False,
                   cli_id=None, repository=None, branch=None, commit_sha=None):
    upload_exit_code = 1
    """Uploads scan results to the AccuKnox endpoint."""
    logger = Logger.get_logger()
    
    if not data_type:
        logger.error("data_type is required for artifact uploads")
        return upload_exit_code
    
    if not os.path.exists(file_path):
        logger.warning(f"Result file not found: {file_path}. Skipping upload.")
        return upload_exit_code

    logger.info(f"Uploading scan results from {file_path} to {endpoint}...")
    headers = {
        "Authorization": f"Bearer {token}"
    }
    if tenant_id:
        headers["Tenant-Id"] = tenant_id
    api_path = "/api/v1/artifact/"
    params = {
        "data_type": data_type,
        "label_id": label,
        "save_to_s3": "true"
    }
    if tenant_id:
        params["tenant_id"] = tenant_id

    # CI/CD quality gate correlation. Only stamp the gate params when this
    # scanner's prefix is one the gate actually supports (GATE_SUPPORTED_PREFIXES)
    # AND repository+branch are present (the backend rejects cli_id without them).
    # Unsupported prefixes (ZAP, MLC, API, DS, ...) upload ungated, exactly as before.
    if cli_id and data_type in GATE_SUPPORTED_PREFIXES and repository and branch:
        params["cli_id"] = cli_id
        params["repository"] = repository
        params["branch"] = branch
        if commit_sha:
            params["commit_sha"] = commit_sha
        logger.info(
            f"CI/CD gate: stamped cli_id={cli_id} for prefix '{data_type}'. "
            f"Pass '{data_type}' to `gate --scanner-prefixes`."
        )
    elif cli_id and data_type not in GATE_SUPPORTED_PREFIXES:
        logger.info(
            f"Prefix '{data_type}' has no quality-gate support; uploading without gate correlation."
        )
    elif cli_id:
        logger.warning(
            "cli_id provided but repository/branch missing; uploading without gate "
            "correlation (this scan will not be evaluated by the CI/CD gate)."
        )

    # Log request details when DEBUG is enabled
    if logger.level == logging.DEBUG:
        url = _build_endpoint_url(endpoint, api_path)
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        logger.debug(f"Upload URL: {url}")
        logger.debug(f"File: {file_path} ({file_size} bytes)")
        logger.debug(f"Parameters: {params}")

    spinner = Spinner(message="Uploading scan results...")
    try:
        spinner.start()

        with open(file_path, 'rb') as file:
            url = _build_endpoint_url(endpoint, api_path)
            response = requests.post(
                url,
                headers=headers,
                params=params,
                files={"file": file},
                verify=False  # Bypass SSL verification
            )
            response.raise_for_status()

        spinner.stop()
        Logger.log_with_color('INFO', "Scan results uploaded successfully!", Fore.GREEN)
        if logger.level == logging.DEBUG:
            logger.debug(f"Response: {response.json()}")
        upload_exit_code = 0

    except requests.exceptions.Timeout:
        spinner.stop()
        logger.error("Upload timed out after 60 seconds.")
        if logger.level == logging.DEBUG:
            logger.debug(f"Endpoint: {endpoint}")

    except requests.exceptions.SSLError as e: 
        spinner.stop()
        logger.error(f"SSL error occurred during upload: {e}")
        if logger.level == logging.DEBUG:
            logger.debug(f"SSL Error Type: {type(e).__name__}")
            logger.debug(f"Endpoint: {endpoint}")

    except requests.exceptions.ConnectionError as e:
        spinner.stop()
        logger.error(f"Connection error occurred during upload: {e}")
        if logger.level == logging.DEBUG:
            logger.debug(f"Connection Error Type: {type(e).__name__}")
            logger.debug(f"Endpoint: {endpoint}")

    except requests.exceptions.RequestException as e:
        spinner.stop()
        logger.error(f"Failed to upload scan results: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response status: {e.response.status_code}")
            logger.error(f"Response body: {e.response.text}")

    except Exception as e:
        spinner.stop()
        logger.error(f"An unexpected error occurred during upload: {e}")
        if logger.level == logging.DEBUG:
            logger.debug(f"Error Type: {type(e).__name__}")

    finally:
        if os.path.exists(file_path):
            if not keep_file:
                os.remove(file_path)
            else:
                logger = Logger.get_logger()
                logger.info(f"Results file kept at: {file_path}")
    
    return upload_exit_code

def poll_gate_status(endpoint, token, cli_id, prefixes, tenant_id=None):
    """Poll the CI/CD quality-gate verdict for a pipeline run.

    GET /api/v1/cicd/scan-status/?cli_id=<uuid>&scanner_prefix=<comma-list>.
    Returns the parsed JSON verdict; raises requests.HTTPError on a non-2xx so the
    caller can distinguish auth (401/403) and not-ready (404) from a real result.
    tenant_id is optional: when present it is stamped on the header and query, else ignored.
    """
    headers = {"Authorization": f"Bearer {token}"}
    if tenant_id:
        headers["Tenant-Id"] = tenant_id
    params = {"cli_id": cli_id}
    if prefixes:
        params["scanner_prefix"] = ",".join(prefixes)
    if tenant_id:
        params["tenant_id"] = tenant_id
    url = _build_endpoint_url(endpoint, "/api/v1/cicd/scan-status/")
    response = requests.get(url, headers=headers, params=params, verify=False, timeout=30)
    response.raise_for_status()
    return response.json()

def handle_failure(exit_code: int, softfail: bool, allow_softfail: bool = True):
    """
    Handles the exit code of an operation.
    The softfail flag is only honored when allow_softfail is True.
    """
    Logger.get_logger().debug(
        f"handle_failure invoked: exit_code={exit_code}, "
        f"softfail={softfail}, allow_softfail={allow_softfail}"
    )
    if exit_code != 0:
        message = f"Completed with non-zero exit code: {exit_code}."
        if softfail and allow_softfail:
            Logger.log_with_color('WARNING', f"{message} (Soft fail enabled, continuing.)", Fore.YELLOW)
        else:
            Logger.log_with_color('ERROR', f"{message} (Hard fail enabled, exiting.)", Fore.RED)
            sys.exit(exit_code)
    else:
        Logger.log_with_color('INFO', "Completed successfully with exit code 0.", Fore.GREEN)
