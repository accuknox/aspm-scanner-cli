import argparse
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.scan.container import ContainerScanner as OriginalContainerScanner # Import original scanner logic

class ContainerScanner(BaseScanner):
    help_text = "Run a container image scan using Trivy"
    data_type_identifier = "TR"

    def add_arguments(self, parser: argparse.ArgumentParser):
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

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_container_scan(args.command, args.container_mode)

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        # Instantiate and run the original scanner logic
        scanner = OriginalContainerScanner(args.command, args.container_mode)
        return scanner.run()