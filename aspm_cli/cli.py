import argparse
import os
from colorama import Fore, init

from aspm_cli.scan.container import ContainerScanner
from aspm_cli.scan.sast import SASTScanner
from aspm_cli.scan.secret import SecretScanner
from aspm_cli.scan.sq_sast import SQSASTScanner
from aspm_cli.scan.dast import DASTScanner
from aspm_cli.utils.git import GitInfo
from aspm_cli.utils import ConfigValidator, ALLOWED_SCAN_TYPES, upload_results, handle_failure
from aspm_cli.scan import IaCScanner
from aspm_cli.utils.spinner import Spinner
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.version import get_version

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

def run_scan(args):
    """Run the specified scan type."""
    try:
        softfail = args.softfail
        accuknox_config = {
            "accuknox_endpoint": args.endpoint or os.getenv("ACCUKNOX_ENDPOINT"),
            "accuknox_tenant": args.tenant or os.getenv("ACCUKNOX_TENANT"),
            "accuknox_label": args.label or os.getenv("ACCUKNOX_LABEL"),
            "accuknox_token": args.token or os.getenv("ACCUKNOX_TOKEN")
        }
        
        # Validate configurations
        validator = ConfigValidator(args.scantype.lower(), **accuknox_config, softfail=softfail)

        # Select scan type and run respective scanner
        if args.scantype.lower() == "iac":
            validator.validate_iac_scan(args.command, args.container_mode, args.repo_url, args.repo_branch)
            scanner = IaCScanner(args.command, args.container_mode, args.repo_url, args.repo_branch)
            data_type = "IAC"
        elif args.scantype.lower() == "sq-sast":
            validator.validate_sq_sast_scan(args.skip_sonar_scan, args.command, args.container_mode, args.repo_url, args.branch, args.commit_sha, args.pipeline_url)
            scanner = SQSASTScanner(args.skip_sonar_scan, args.command, args.container_mode, args.repo_url, args.branch, args.commit_sha, args.pipeline_url)
            data_type = "SQ"
        elif args.scantype.lower() == "secret":
            validator.validate_secret_scan(args.command, args.container_mode)
            scanner = SecretScanner(args.command, args.container_mode)
            data_type = "TruffleHog"
        elif args.scantype.lower() == "container":
            validator.validate_container_scan(args.command, args.container_mode)
            scanner = ContainerScanner(args.command, args.container_mode)
            data_type = "TR"
        elif args.scantype.lower() == "sast":
            validator.validate_sast_scan(args.repo_url, args.commit_ref, args.commit_sha, args.pipeline_id, args.job_url)
            scanner = SASTScanner(args.repo_url, args.commit_ref, args.commit_sha, args.pipeline_id, args.job_url)
            data_type = "SG"
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

def add_iac_scan_args(parser):
    """Add arguments specific to IAC scan."""
    parser.add_argument(
        "--command",
        required=True,
        help="Arguments to pass to the IAC scanner (e.g., '-d .')"
    )
    parser.add_argument(
        "--container-mode",
        action="store_true",
        help="Run in container mode"
    )
    parser.add_argument("--repo-url", default=GitInfo.get_repo_url(), help="Git repository URL")
    parser.add_argument("--repo-branch", default=GitInfo.get_branch_name(), help="Git repository branch")

def add_sast_scan_args(parser):
    """Add arguments specific to SAST scan."""
    parser.add_argument("--repo-url", default=GitInfo.get_repo_url(), help="Git repository URL")
    parser.add_argument("--commit-ref", default=GitInfo.get_commit_ref(), help="Commit reference for scanning")
    parser.add_argument("--commit-sha", default=GitInfo.get_commit_sha(), help="Commit SHA for scanning")
    parser.add_argument("--pipeline-id", help="Pipeline ID for scanning")
    parser.add_argument("--job-url", help="Job URL for scanning")

def add_container_scan_args(parser):
    """Add CLI arguments for the container scanning module."""
    parser.add_argument(
        "--command",
        type=str,
        required=True,
        help="Arguments to pass to the container scanner (e.g., 'image nginx:latest')"
    )
    parser.add_argument(
        "--container-mode",
        action="store_true",
        help="Run in container mode"
    )
def add_sq_sast_scan_args(parser):
    """Add arguments specific to SQ SAST scan."""
    parser.add_argument('--skip-sonar-scan', action='store_true', help="Skip the SonarQube scan")

    parser.add_argument(
        "--command",
        type=str,
        required=True,
        help="Arguments to pass to the SQ scanner (e.g., '-Dsonar.projectKey='<PROJECT KEY>' -Dsonar.host.url=<HOST URL> -Dsonar.token=<TOKEN> -Dsonar.organization=<ORG ID>')"
    )
    parser.add_argument(
        "--container-mode",
        action="store_true",
        help="Run in container mode"
    )

    parser.add_argument("--repo-url", default=GitInfo.get_repo_url(), help="Git repository URL")
    parser.add_argument("--branch", default=GitInfo.get_branch_name(), help="Git repository branch")
    parser.add_argument("--commit-sha", default=GitInfo.get_commit_sha(), help="Commit SHA for scanning")
    parser.add_argument("--pipeline-url", help="Pipeline URL for scanning")

def add_secret_scan_args(parser):
    """Add arguments specific to Secret Scan."""
    parser.add_argument(
        "--command",
        type=str,
        required=True,
        help="Arguments to pass to the secret scanner (e.g., 'git file://.')"
    )
    parser.add_argument(
        "--container-mode",
        action="store_true",
        help="Run in container mode"
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
    parser.add_argument('--version', action='version', version=f"%(prog)s v{get_version()}")

    # Scan options
    parser.add_argument('--endpoint', help='The URL of the Control panel to push the scan results to.')
    parser.add_argument('--tenant', help='The ID of the tenant associated with the Control panel.	')
    parser.add_argument('--label', help='The label created in AccuKnox for associating scan results.	')
    parser.add_argument('--token', help='The token for authenticating with the Control Panel')

    # Scan options
    scan_parser = subparsers.add_parser("scan", help=f"Run a scan (e.g. {', '.join(ALLOWED_SCAN_TYPES)})")
    scan_subparsers = scan_parser.add_subparsers(dest="scantype")

    # IAC Scan
    iac_parser = scan_subparsers.add_parser("iac", help="Run IAC scan")
    add_iac_scan_args(iac_parser)
    iac_parser.set_defaults(func=run_scan)

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

    # ----------------------------- Non Container Mode does not supported ----------------------------- #
    # DAST Scan
    dast_parser = scan_subparsers.add_parser("dast", help="Run a DAST scan")
    add_dast_scan_args(dast_parser)
    dast_parser.set_defaults(func=run_scan)

    # SAST Scan
    sast_parser = scan_subparsers.add_parser("sast", help="Run SAST scan")
    add_sast_scan_args(sast_parser) 
    sast_parser.set_defaults(func=run_scan)
    # ----------------------------- Non Container Mode does not supported ----------------------------- #

    # Parse arguments and execute respective function
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
