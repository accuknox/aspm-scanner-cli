import argparse

from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.scan.api_discovery import APIDiscoveryScanner as OriginalAPIDiscoveryScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.git_info import GitInfo


class APIDiscoveryScanner(BaseScanner):
    help_text = "Run API discovery scan using code2api (static route discovery from source)"
    data_type_identifier = "API"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--command",
            type=str,
            default="-path . -output results.json",
            help="code2api args (default: '-path . -output results.json')",
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run code2api in container mode",
        )
        parser.add_argument(
            "--repo-url",
            default=GitInfo.get_repo_url(),
            help="Repository URL (recorded in CI; optional metadata for uploads)",
        )

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_api_discovery_scan(args.command, args.container_mode)

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalAPIDiscoveryScanner(args.command, args.container_mode)
        return scanner.run()
