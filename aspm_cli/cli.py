import argparse
import os
from colorama import Fore, init

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
    banner = r"""
    ╔═╗┌─┐┌─┐┬ ┬╦╔═┌┐┌┌─┐─┐ ┬  ╔═╗╔═╗╔═╗╔╦╗  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
    ╠═╣│  │  │ │╠╩╗││││ │┌┴┬┘  ╠═╣╚═╗╠═╝║║║  ╚═╗│  ├─┤││││││├┤ ├┬┘
    ╩ ╩└─┘└─┘└─┘╩ ╩┘└┘└─┘┴ └─  ╩ ╩╚═╝╩  ╩ ╩  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
    """
    print(Fore.BLUE + banner)

def print_env(args):
    """Print environment configurations."""
    try:
        for var in ['ACCUKNOX_ENDPOINT', 'ACCUKNOX_TENANT', 'ACCUKNOX_LABEL']:
            Logger.get_logger().info(f"{var}={os.getenv(var)}")
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
            scanner = IaCScanner(args.repo_url, args.repo_branch, args.file, args.directory, args.compact, args.quiet, args.framework)
            data_type = "IAC"
        else:
            Logger.get_logger().error("Invalid scan type.")
            return

        # Run scan with spinner
        spinner = Spinner(message=f"Running {args.scantype.lower()} scan...", color=Fore.GREEN)
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
    parser.add_argument("--file", default="", help="Specify a file for scanning; cannot be used with directory input")
    parser.add_argument("--directory", default="./", help="Directory with infrastructure code and/or package manager files to scan")
    parser.add_argument("--compact", action="store_true", help="Do not display code blocks in output")
    parser.add_argument("--quiet", action="store_true", help="Display only failed checks")
    parser.add_argument("--framework", default="all", help="Filter scans by specific frameworks, e.g., --framework terraform,sca_package. For all frameworks, use --framework all")
    parser.add_argument("--repo-url", default=GitInfo.get_repo_url(), help="Git repository URL")
    parser.add_argument("--repo-branch", default=GitInfo.get_branch_name(), help="Git repository branch")

def main():
    clean_env_vars()
    print_banner()
    parser = argparse.ArgumentParser(prog="aspm-cli", description="ASPM CLI Tool")
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

    # Parse arguments and execute respective function
    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()