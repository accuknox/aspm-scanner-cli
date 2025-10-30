import argparse
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.git_info import GitInfo
from aspm_cli.scan import IaCScanner as OriginalIaCScanner

class IACScanner(BaseScanner):
    help_text = "Run Infrastructure as Code (IaC) scan using Checkov"
    data_type_identifier = "IAC"

    def add_arguments(self, parser: argparse.ArgumentParser):
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

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_iac_scan(args.command, args.container_mode, args.repo_url, args.repo_branch)

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalIaCScanner(args.command, args.container_mode, args.repo_url, args.repo_branch)
        return scanner.run()