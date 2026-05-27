import argparse
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.scan.container import ContainerScanner as OriginalContainerScanner

class ContainerScanner(BaseScanner):
    help_text = "Run a container image or filesystem SBOM scan"
    data_type_identifier = "TR"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--command",
            type=str,
            required=True,
            help=(
                "Scanner arguments (e.g. 'image nginx:latest' for image SBOM/vuln scan; "
                "'filesystem .' for repo SBOM with --generate-sbom)"
            )
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode"
        )
        parser.add_argument(
            "--generate-sbom",
            action="store_true",
            help="Generate SBOM instead of running a vulnerability scan"
        )

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_container_scan(
            args.command,
            args.container_mode,
            generate_sbom=getattr(args, "generate_sbom", False),
        )

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        # Instantiate and run the original scanner logic
        generate_sbom = getattr(args, "generate_sbom", False)
        scanner = OriginalContainerScanner(args.command, args.container_mode, generate_sbom=generate_sbom)
        return scanner.run()