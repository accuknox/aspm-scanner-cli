import argparse

from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.scan.ml_scan import MLScanScanner as OriginalMLScanScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.git_info import GitInfo


class MLScanScanner(BaseScanner):
    help_text = "Run ML static model scan using ModelScan"
    data_type_identifier = "MLCHECKS"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--command",
            type=str,
            default="scan -p . -r json",
            help="ModelScan args (default: 'scan -p . -r json'; discovers model files under -p path)",
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode",
        )
        parser.add_argument(
            "--repo-url",
            default=GitInfo.get_repo_url(),
            help="Repository URL or CI project path (used in upload metadata)",
        )
        parser.add_argument(
            "--commit-ref",
            default=GitInfo.get_commit_ref(),
            help="Branch or ref (used in model_path metadata)",
        )
        parser.add_argument(
            "--model-name",
            help="Collector/project name in ondemand_modelscan payload (defaults to repo name)",
        )
        parser.add_argument(
            "--source-type",
            default="github",
            help="Source type in upload payload (default: github)",
        )

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        validator.validate_ml_scan(
            args.command,
            args.container_mode,
            args.repo_url,
            args.commit_ref,
            args.model_name,
            args.source_type,
        )

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalMLScanScanner(
            command=args.command,
            container_mode=args.container_mode,
            repo_url=args.repo_url,
            commit_ref=args.commit_ref,
            model_name=args.model_name,
            source_type=args.source_type,
        )
        return scanner.run()
