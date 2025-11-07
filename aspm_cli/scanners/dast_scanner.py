import argparse
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.scan.dast import DASTScanner as OriginalDASTScanner # Import original scanner logic

class DASTScanner(BaseScanner):
    help_text = "Run a DAST scan using OWASP ZAP"
    data_type_identifier = "ZAP"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--severity-threshold",
            default="HIGH",
            help="Severity level to fail the scan. Allowed values: LOW, MEDIUM, HIGH. Default is HIGH"
        )
        parser.add_argument(
            "--command",
            required=True,
            help="Arguments to pass to the DAST scanner (e.g., 'zap-baseline.py -t https://example.com -I')"
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode"
        )

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_dast_scan(args.command, args.severity_threshold, args.container_mode)

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalDASTScanner(args.command, args.severity_threshold, args.container_mode)
        return scanner.run()