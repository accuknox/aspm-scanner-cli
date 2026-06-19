import argparse

from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.scan.sca import SCAScanner as OriginalSCAScanner
from aspm_cli.utils.config import ConfigValidator


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

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_sca_scan(args.command, args.container_mode, args.severity)

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalSCAScanner(
            args.command,
            args.container_mode,
            severity=args.severity,
        )
        return scanner.run()
