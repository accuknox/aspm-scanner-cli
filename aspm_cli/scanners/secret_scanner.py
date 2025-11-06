import argparse
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.scan.secret import SecretScanner as OriginalSecretScanner

class SecretScanner(BaseScanner):
    help_text = "Run Secret scan using TruffleHog"
    data_type_identifier = "TruffleHog"

    def add_arguments(self, parser: argparse.ArgumentParser):
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

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_secret_scan(args.command, args.container_mode)

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalSecretScanner(args.command, args.container_mode)
        return scanner.run()