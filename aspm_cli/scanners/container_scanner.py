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
        parser.add_argument(
            "--sbom-format",
            choices=("cyclonedx", "spdx"),
            default="cyclonedx",
            help="SBOM standard to generate with --generate-sbom (default: cyclonedx)"
        )
        parser.add_argument(
            "--sbom-author",
            type=str,
            default=None,
            help=(
                "Author recorded in the SBOM (CERT-In 'Author of SBOM data'). "
                "Default: ACCUKNOX_SBOM_AUTHOR, the CI actor, the git identity, then the scanner."
            )
        )
        parser.add_argument(
            "--sbom-output",
            type=str,
            default=None,
            help="Also write the finished SBOM to this file (the upload still uses ./results.json)"
        )
        parser.add_argument(
            "--sbom-version",
            type=int,
            default=None,
            help="Revision number written as the SBOM's version (CycloneDX 'version'); the scanner always writes 1"
        )
        parser.add_argument(
            "--sbom-vex",
            action="append",
            default=None,
            metavar="FILE",
            help=(
                "VEX file (OpenVEX, CycloneDX VEX or CSAF) to apply; repeatable. Trivy drops the CVEs it marks "
                "not affected or fixed, and the statements are recorded in the SBOM as vulnerabilities[].analysis"
            )
        )
        parser.add_argument(
            "--cert-in-check",
            action="store_true",
            help=(
                "Check the generated SBOM against the CERT-In minimum data fields and exit 1 "
                "unless it is conformant"
            )
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
        scanner = OriginalContainerScanner(
            args.command,
            args.container_mode,
            generate_sbom=generate_sbom,
            sbom_format=getattr(args, "sbom_format", "cyclonedx"),
            vex_files=getattr(args, "sbom_vex", None),
        )
        return scanner.run()