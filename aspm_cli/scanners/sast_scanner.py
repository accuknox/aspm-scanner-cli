import argparse
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.git_info import GitInfo
from aspm_cli.scan.sast import SASTScanner as OriginalSASTScanner 

class SASTScanner(BaseScanner):
    help_text = "Run Static Application Security Testing (SAST) scan using Semgrep"
    data_type_identifier = "SG"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--command",
            required=True,
            help="Arguments to pass to the SAST scanner (e.g., 'scan .')"
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode"
        )
        parser.add_argument(
            "--severity",
            default="INFO,WARNING,LOW,MEDIUM,HIGH,CRITICAL",
            help="Comma-separated list of severities to check. If any match, the scan will fail. Defaults to all severities."
        )
        parser.add_argument("--repo-url", default=GitInfo.get_repo_url(), help="Git repository URL")
        parser.add_argument("--commit-ref", default=GitInfo.get_commit_ref(), help="Commit reference for scanning")
        parser.add_argument("--commit-sha", default=GitInfo.get_commit_sha(), help="Commit SHA for scanning")
        parser.add_argument("--pipeline-id", help="Pipeline ID for scanning")
        parser.add_argument("--job-url", help="Job URL for scanning")

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_sast_scan(
            args.command, args.container_mode, args.severity, args.repo_url,
            args.commit_ref, args.commit_sha, args.pipeline_id, args.job_url
        )

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalSASTScanner(
            args.command, args.container_mode, args.severity, args.repo_url,
            args.commit_ref, args.commit_sha, args.pipeline_id, args.job_url
        )
        return scanner.run()