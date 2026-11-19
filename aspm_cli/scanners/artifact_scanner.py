"""Argument definitions for the artifact workflows handled by ScanCommand."""
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.artifact_engine import TARGET_TYPES


def add_target_arguments(parser):
    parser.add_argument("--target-type", choices=TARGET_TYPES, default="auto")
    parser.add_argument("--asset-name", help="Stable application/artifact name across builds")
    parser.add_argument("--output-dir", help="Directory for result.json, SBOM and reports (outside the input)")
    parser.add_argument("--offline", action="store_true", help="Use already cached vulnerability databases")
    parser.add_argument("--cache-dir", help="Scanner database cache directory")
    parser.add_argument("--idempotency-key", help="Submission key for retrying an identical report upload")


class SBOMScanner(BaseScanner):
    help_text = "Generate an SBOM for a directory, manifest, executable or archive"

    def add_arguments(self, parser):
        parser.add_argument("--target", required=True)
        parser.add_argument("--container-mode", action="store_true")
        add_target_arguments(parser)

    def validate_config(self, args, validator):
        pass

    def run_scan(self, args):
        raise NotImplementedError("Handled by the artifact workflow")


class MobileScanner(SBOMScanner):
    help_text = "Submit an APK/IPA to backend mobile security analysis"

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--target", help="APK or IPA file")
        group.add_argument("--run-id", help="Retrieve/wait for a previously submitted run")
        parser.add_argument("--mode", choices=("static", "static_dynamic", "sbom"), default="static")
        parser.add_argument("--dynamic-duration", type=int, choices=range(30, 301), default=60, metavar="30-300")
        parser.add_argument("--asset-name")
        parser.add_argument("--output-dir")
        parser.add_argument("--no-wait", action="store_true")
        parser.add_argument("--timeout", type=int, default=3600)
        parser.add_argument("--severity", default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
        parser.add_argument("--idempotency-key", help="Reuse a submission after a CI retry")
