import argparse
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.git_info import GitInfo
from aspm_cli.scan.sq_sast import SQSASTScanner as OriginalSQSASTScanner # Import original scanner logic

class SQSASTScanner(BaseScanner):
    help_text = "Run SonarQube Static Application Security Testing (SAST) scan"
    data_type_identifier = "SQ"

    def add_arguments(self, parser: argparse.ArgumentParser):
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

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_sq_sast_scan(
            args.skip_sonar_scan, args.command, args.container_mode,
            args.repo_url, args.branch, args.commit_sha, args.pipeline_url
        )

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        # Instantiate and run the original scanner logic
        scanner = OriginalSQSASTScanner(
            args.skip_sonar_scan, args.command, args.container_mode,
            args.repo_url, args.branch, args.commit_sha, args.pipeline_url
        )
        return scanner.run()