import argparse

from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.scan.secret import SecretScanner as OriginalSecretScanner
from aspm_cli.utils.config import ConfigValidator


class SecretScanner(BaseScanner):
    help_text = "Run secret scan using TruffleHog or Gitleaks"
    data_type_identifier = "TruffleHog"

    def __init__(self, engine: str = "trufflehog"):
        super().__init__()
        self.engine = engine.lower()
        self.data_type_identifier = "Gitleaks" if self.engine == "gitleaks" else "TruffleHog"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--command",
            type=str,
            required=True,
            help="Scanner args (TruffleHog: 'filesystem .'; Gitleaks: 'detect --source .')",
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode",
        )
        parser.add_argument(
            "--engine",
            choices=["trufflehog", "gitleaks"],
            default="trufflehog",
            help="Secret scanner engine (default: trufflehog)",
        )

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_secret_scan(args.command, args.container_mode, args.engine)

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        engine = args.engine.lower()
        self.engine = engine
        self.data_type_identifier = "Gitleaks" if engine == "gitleaks" else "TruffleHog"
        scanner = OriginalSecretScanner(args.command, args.container_mode, engine=engine)
        return scanner.run()
