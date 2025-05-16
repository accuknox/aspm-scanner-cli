import argparse
import os
from colorama import Fore, init

from aspm_cli.scan.container import ContainerScanner
from aspm_cli.scan.sast import SASTScanner
from aspm_cli.scan.secret import SecretScanner
from aspm_cli.scan.sq_sast import SQSASTScanner
from aspm_cli.scan.dast import DASTScanner
from aspm_cli.utils.git import GitInfo
from .utils import ConfigValidator, ALLOWED_SCAN_TYPES, upload_results, handle_failure
from .scan import IaCScanner
from .utils.spinner import Spinner
from .utils.logger import Logger

init(autoreset=True)

def clean_env_vars():
    """Removes surrounding quotes from all environment variables."""
    for key, value in os.environ.items():
        if value and (value.startswith(("'", '"')) and value.endswith(("'", '"'))):
            os.environ[key] = value[1:-1]

def print_banner():
    try:
        banner = r"""
        ╔═╗┌─┐┌─┐┬ ┬╦╔═┌┐┌┌─┐─┐ ┬  ╔═╗╔═╗╔═╗╔╦╗  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
        ╠═╣│  │  │ │╠╩╗││││ │┌┴┬┘  ╠═╣╚═╗╠═╝║║║  ╚═╗│  ├─┤││││││├┤ ├┬┘
        ╩ ╩└─┘└─┘└─┘╩ ╩┘└┘└─┘┴ └─  ╩ ╩╚═╝╩  ╩ ╩  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
        """
        print(Fore.BLUE + banner)
    except:
        # Skipping if there are any issues with Unicode chars
        print(Fore.BLUE + "ACCUKNOX ASPM SCANNER")

def print_env(args):
    """Print environment configurations."""
    try:
        for var in ['ACCUKNOX_ENDPOINT', 'ACCUKNOX_TENANT', 'ACCUKNOX_LABEL']:
            Logger.get_logger().info(f"{var}={os.getenv(var)}")
        
        accuknox_token = os.getenv('ACCUKNOX_TOKEN')
        if accuknox_token:
            Logger.get_logger().info(f"ACCUKNOX_TOKEN={accuknox_token[:5]}...{accuknox_token[-5:]}")  # First 5 and last 5 characters
        else:
            Logger.get_logger().info("ACCUKNOX_TOKEN not set")

    except Exception as e:
        Logger.get_logger().error(f"Error printing environment variables: {e}")

def run_scan(args):
    """Run the specified scan type."""
    try:
        softfail = args.softfail
        accuknox_config = {
            "accuknox_endpoint": os.getenv("ACCUKNOX_ENDPOINT"),
            "accuknox_tenant": os.getenv("ACCUKNOX_TENANT"),
            "accuknox_label": os.getenv("ACCUKNOX_LABEL"),
            "accuknox_token": os.getenv("ACCUKNOX_TOKEN")
        }
        
        # Validate configurations
        validator = ConfigValidator(args.scantype.lower(), **accuknox_config, softfail=softfail)

        # Select scan type and run respective scanner
        if args.scantype.lower() == "iac":
            validator.validate_iac_scan(args.repo_url, args.repo_branch, args.file, args.directory, args.compact, args.quiet, args.framework)
            scanner = IaCScanner(args.repo_url, args.repo_branch, args.file, args.directory, args.compact, args.quiet, args.framework, args.base_command)
            data_type = "IAC"
        elif args.scantype.lower() == "sast":
            validator.validate_sast_scan(args.repo_url, args.commit_ref, args.commit_sha, args.pipeline_id, args.job_url)
            scanner = SASTScanner(args.repo_url, args.commit_ref, args.commit_sha, args.pipeline_id, args.job_url)
            data_type = "SG"
        elif args.scantype.lower() == "sq-sast":
            validator.validate_sq_sast_scan(args.sonar_project_key, args.sonar_token, args.sonar_host_url, args.sonar_org_id, args.repo_url, args.branch, args.commit_sha, args.pipeline_url)
            scanner = SQSASTScanner(args.skip_sonar_scan, args.sonar_project_key, args.sonar_token, args.sonar_host_url, args.sonar_org_id, args.repo_url, args.branch, args.commit_sha, args.pipeline_url, args.base_command)
            data_type = "SQ"
        elif args.scantype.lower() == "secret":
            validator.validate_secret_scan(args.results, args.branch, args.exclude_paths, args.additional_arguments)
            scanner = SecretScanner(args.results, args.branch, args.exclude_paths, args.additional_arguments, args.base_command)
            data_type = "TruffleHog"
        elif args.scantype.lower() == "container":
            validator.validate_container_scan(args.image_name, args.tag, args.severity)
            scanner = ContainerScanner(args.image_name, args.tag, args.severity, args.base_command)
            data_type = "TR"
        elif args.scantype.lower() == "dast":
            validator.validate_dast_scan(args.target_url, args.severity_threshold, args.dast_scan_type)
            scanner = DASTScanner(args.target_url, args.severity_threshold, args.dast_scan_type)
            data_type = "ZAP"
        else:
            Logger.get_logger().error("Invalid scan type.")
            return

        # Run scan with spinner
        spinner = Spinner(message=f"Running {args.scantype.lower()} scan...")
        spinner.start()
        exit_code, result_file = scanner.run()
        spinner.stop()

        # Upload results and handle failure
        if result_file:
            upload_results(result_file, accuknox_config["accuknox_endpoint"], accuknox_config["accuknox_tenant"], accuknox_config["accuknox_label"], accuknox_config["accuknox_token"], data_type)
        handle_failure(exit_code, softfail)
    except Exception as e:
        Logger.get_logger().error("Scan failed.")
        Logger.get_logger().error(e)

# TODO: update all description, and mention optional fields
def add_iac_scan_args(parser):
    """Add arguments specific to IAC scan."""
    parser.add_argument("--file", default="", help="Specify a file for scanning; cannot be used with directory input")
    parser.add_argument("--directory", default="./", help="Directory with infrastructure code and/or package manager files to scan")
    parser.add_argument("--compact", action="store_true", help="Do not display code blocks in output")
    parser.add_argument("--quiet", action="store_true", help="Display only failed checks")
    parser.add_argument("--framework", default="all", help="Filter scans by specific frameworks, e.g., --framework terraform,sca_package. For all frameworks, use --framework all")
    parser.add_argument("--repo-url", default=GitInfo.get_repo_url(), help="Git repository URL")
    parser.add_argument("--repo-branch", default=GitInfo.get_branch_name(), help="Git repository branch")
    parser.add_argument(
        "--base-command",
        help=(
            "Optional override for the base command used to run IAC Scan"
            "Use this to switch from the default Docker-based execution to a custom command. "
            "For example, to run checkov locally: 'checkov'. "
            "Or to run it with a custom Docker version: 'docker run --rm -v $PWD:/workdir --workdir /workdir ghcr.io/bridgecrewio/checkov:3.2.21', (ensure /workdir is mounted to the scan directory)"
        )
    )

def add_sast_scan_args(parser):
    """Add arguments specific to SAST scan."""
    parser.add_argument("--repo-url", default=GitInfo.get_repo_url(), help="Git repository URL")
    parser.add_argument("--commit-ref", default=GitInfo.get_commit_ref(), help="Commit reference for scanning")
    parser.add_argument("--commit-sha", default=GitInfo.get_commit_sha(), help="Commit SHA for scanning")
    parser.add_argument("--pipeline-id", help="Pipeline ID for scanning")
    parser.add_argument("--job-url", help="Job URL for scanning")

def add_container_scan_args(parser):
    """Add arguments specific to Container Scan."""
    parser.add_argument(
        "--image-name",
        required=True,
        help="Name of the Docker image to scan (without tag)."
    )
    parser.add_argument(
        "--tag",
        required=True,
        help="Tag of the Docker image to scan"
    )
    parser.add_argument(
        "--severity",
        default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        help="Comma-separated list of severities to check. If any match, the scan will fail. Defaults to all severities."
    )
    parser.add_argument(
        "--base-command",
        help=(
            "Optional override for the base command used to run Container Scan"
            "Use this to switch from the default Docker-based execution to a custom command. "
            "For example, to run trivy locally: 'trivy'. "
            "Or to run it with a custom Docker version: 'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v /home/redshadow/accuknox/aspm-scanner-cli:/workdir --workdir /workdir aquasec/trivy:0.62.1', (ensure /workdir is mounted to the scan directory)"
        )
    )

def add_sq_sast_scan_args(parser):
    """Add arguments specific to SQ SAST scan."""
    # TODO: update description
    parser.add_argument('--skip-sonar-scan', action='store_true', help="Skip the SonarQube scan")
    parser.add_argument("--sonar-project-key", help="")
    parser.add_argument("--sonar-token", help="")
    parser.add_argument("--sonar-host-url", help="")
    parser.add_argument("--sonar-org-id", help="")

    parser.add_argument("--repo-url", default=GitInfo.get_repo_url(), help="Git repository URL")
    parser.add_argument("--branch", default=GitInfo.get_branch_name(), help="Git repository branch")
    parser.add_argument("--commit-sha", default=GitInfo.get_commit_sha(), help="Commit SHA for scanning")
    parser.add_argument("--pipeline-url", help="Pipeline URL for scanning")
    parser.add_argument(
        "--base-command",
        help=(
            "Optional override for the base command used to run SQ SAST Scan"
            "Use this to switch from the default Docker-based execution to a custom command. "
            "For example, to run SQ Scan locally: 'sonar-scanner'. "
            "Or to run it with a custom Docker version: ' docker run --rm -v $PWD:/usr/src/ sonarsource/sonar-scanner-cli:11.3', (ensure /usr/src is mounted to the scan directory)"
        )
    )

def add_secret_scan_args(parser):
    """Add arguments specific to Secret Scan."""
    parser.add_argument("--results", help="Specifies which type(s) of results to output: verified, unknown, unverified, filtered_unverified. Defaults to all types.")
    parser.add_argument("--branch", default=GitInfo.get_commit_sha(), help="The branch to scan. Use all-branches to scan all branches. (default: latest commit sha)")
    parser.add_argument("--exclude-paths", help="Paths to exclude from the scan")
    parser.add_argument("--additional-arguments", help="Additional CLI arguments to pass to Secret Scan")
    parser.add_argument(
        "--base-command",
        help=(
            "Optional override for the base command used to run Secret Scan"
            "Use this to switch from the default Docker-based execution to a custom command. "
            "For example, to run TruffleHog locally: 'trufflehog'. "
            "Or to run it with a custom Docker version: 'docker run --rm -v $PWD:/app trufflesecurity/trufflehog:3.88.29', (ensure /app is mounted to the scan directory)"
        )
    )

def add_dast_scan_args(parser):
    """Add arguments specific to DAST scan."""
    parser.add_argument(
        "--target-url",
        required=True,
        help="The target web application URL to scan (must start with http or https)"
    )
    parser.add_argument(
        "--severity-threshold",
        default="High",
        help="Severity level to fail the scan. Allowed values: LOW, MEDIUM, HIGH. Default is HIGH"
    )
    parser.add_argument(
        "--dast-scan-type",
        default="baseline",
        help="DAST scan type to run. Allowed values: baseline, full-scan. Default is baseline"
    )

def main():
    clean_env_vars()
    print_banner()
    parser = argparse.ArgumentParser(prog="accuknox-aspm-scanner", description="ASPM CLI Tool")
    subparsers = parser.add_subparsers(dest="command")

    parser.add_argument('--softfail', action='store_true', help='Enable soft fail mode for scanning')

    # Environment validation
    env_parser = subparsers.add_parser("env", help="Validate and print config from environment")
    env_parser.set_defaults(func=print_env)

    # Scan options
    scan_parser = subparsers.add_parser("scan", help=f"Run a scan (e.g. {', '.join(ALLOWED_SCAN_TYPES)})")
    scan_subparsers = scan_parser.add_subparsers(dest="scantype")

    # IAC Scan
    iac_parser = scan_subparsers.add_parser("iac", help="Run IAC scan")
    add_iac_scan_args(iac_parser)
    iac_parser.set_defaults(func=run_scan)

    # SAST Scan
    sast_parser = scan_subparsers.add_parser("sast", help="Run SAST scan")
    add_sast_scan_args(sast_parser) 
    sast_parser.set_defaults(func=run_scan)

    # SQ SAST Scan
    sq_sast_parser = scan_subparsers.add_parser("sq-sast", help="Run SQ SAST scan")
    add_sq_sast_scan_args(sq_sast_parser) 
    sq_sast_parser.set_defaults(func=run_scan)

    # Secret Scan
    secret_parser = scan_subparsers.add_parser("secret", help="Run Secret scan")
    add_secret_scan_args(secret_parser) 
    secret_parser.set_defaults(func=run_scan)

    # Container Scan
    container_parser = scan_subparsers.add_parser("container", help="Run a container image scan")
    add_container_scan_args(container_parser)
    container_parser.set_defaults(func=run_scan)

    # DAST Scan
    dast_parser = scan_subparsers.add_parser("dast", help="Run a DAST scan")
    add_dast_scan_args(dast_parser)
    dast_parser.set_defaults(func=run_scan)

    # Parse arguments and execute respective function
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()