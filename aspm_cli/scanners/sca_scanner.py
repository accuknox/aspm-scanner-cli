import argparse

from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.scan.sca import SCAScanner as OriginalSCAScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.git_info import GitInfo


class SCAScanner(BaseScanner):
    help_text = "Run Software Composition Analysis (SCA) using Trivy filesystem scan"
    data_type_identifier = "TR"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--command",
            type=str,
            required=True,
            help="Trivy filesystem args (e.g. 'fs .')",
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode",
        )
        parser.add_argument(
            "--severity",
            default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            help="Comma-separated severities that fail the scan",
        )
        parser.add_argument(
            "--repo-url",
            default=GitInfo.get_repo_url(),
            help="Git repository URL (used for SCA asset identity; defaults from git)",
        )
        parser.add_argument(
            "--repo-branch",
            default=GitInfo.get_branch_name(),
            help="Git repository branch (used for SCA asset identity; defaults from git)",
        )

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_sca_scan(
            args.command,
            args.container_mode,
            args.severity,
            args.repo_url,
            args.repo_branch,
        )

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalSCAScanner(
            args.command,
            args.container_mode,
            severity=args.severity,
            repo_url=args.repo_url,
            repo_branch=args.repo_branch,
        )
        return scanner.run()
