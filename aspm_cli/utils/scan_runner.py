"""Run one scanner and upload its result; shared by ``scan`` and ``pipeline``.

Split into a scan phase and an upload phase so ``pipeline`` can run every scan first and then
declare to the quality gate exactly the scans that produced results.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass

from aspm_cli.scanners import scanner_registry
from aspm_cli.utils.common import upload_results
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.sbom import (
    derive_sbom_classifier,
    enrich_sbom_payload,
    is_sbom_payload_empty,
    resolve_project_name,
)
from aspm_cli.utils.spinner import Spinner


@dataclass
class ScanRun:
    """Outcome of the scan phase."""

    scantype: str
    data_type: str
    exit_code: int
    result_file: str | None
    is_sbom: bool = False


@dataclass
class UploadOutcome:
    """Outcome of the upload phase. ``empty_sbom`` means the upload was skipped on purpose."""

    exit_code: int = 0
    uploaded: bool = False
    empty_sbom: bool = False


def build_accuknox_config(args) -> dict:
    """Upload settings from flags (before the scan name) or ACCUKNOX_* variables."""
    return {
        "accuknox_endpoint": args.endpoint or os.getenv("ACCUKNOX_ENDPOINT"),
        "accuknox_label": args.label or os.getenv("ACCUKNOX_LABEL"),
        "accuknox_token": args.token or os.getenv("ACCUKNOX_TOKEN"),
        "accuknox_tenant": args.tenant or os.getenv("ACCUKNOX_TENANT"),
        "accuknox_project_name": resolve_project_name(args.project_name),
    }


def scanner_args(registry_key: str, argv: list[str]) -> argparse.Namespace:
    """Parse ``argv`` with a scanner's own argument definition, so pipeline runs get its defaults."""
    parser = argparse.ArgumentParser(prog=registry_key.lower(), add_help=False, exit_on_error=False)
    scanner_registry[registry_key]().add_arguments(parser)
    try:
        namespace = parser.parse_args(argv)
    except (argparse.ArgumentError, SystemExit) as exc:
        raise ValueError(f"Invalid options for the {registry_key.lower()} scan: {exc}") from None
    namespace.scantype = registry_key
    return namespace


def run_scan(args, accuknox_config: dict, softfail: bool, skip_upload: bool) -> ScanRun:
    """Validate and run one scanner (``args.scantype`` is its registry key). SBOM output is enriched."""
    scantype = args.scantype
    scanner = scanner_registry[scantype]()
    validator = ConfigValidator(scantype.lower(), **accuknox_config, softfail=softfail, skip_upload=skip_upload)
    scanner.validate_config(args, validator)

    spinner = Spinner(message=f"Running {scantype.lower()} scan...")
    spinner.start()
    try:
        exit_code, result_file = scanner.run_scan(args)
    finally:
        spinner.stop()

    # A container scan with --generate-sbom is uploaded as an SBOM, enriched with the project name.
    is_sbom = scantype.lower() == "container" and getattr(args, "generate_sbom", False)
    if is_sbom and result_file and os.path.exists(result_file):
        project_classifier = derive_sbom_classifier(getattr(args, "command", "") or "")
        try:
            with open(result_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                enrich_sbom_payload(
                    data,
                    getattr(args, "command", "") or "",
                    accuknox_config.get("accuknox_project_name"),
                    project_classifier,
                )
                with open(result_file, "w", encoding="utf-8") as handle:
                    json.dump(data, handle, indent=2)
        except Exception as exc:
            Logger.get_logger().debug(f"Failed to enrich SBOM results.json: {exc}")

    return ScanRun(
        scantype=scantype,
        data_type="SBOM" if is_sbom else scanner.get_data_type_identifier(),
        exit_code=exit_code,
        result_file=result_file,
        is_sbom=is_sbom,
    )


def discard_result(run: ScanRun, keep_results: bool) -> None:
    """Clean up (or keep) a result file that will not be uploaded."""
    if not run.result_file or not os.path.exists(run.result_file):
        return
    if keep_results:
        Logger.get_logger().info(f"Results file kept at: {run.result_file}")
    else:
        os.remove(run.result_file)


def is_empty_sbom(run: ScanRun) -> bool:
    """True for an SBOM result with no components: it is not uploaded, so nothing may wait for it."""
    if not run.is_sbom or not run.result_file:
        return False
    try:
        with open(run.result_file, "r", encoding="utf-8") as handle:
            return is_sbom_payload_empty(json.load(handle))
    except (json.JSONDecodeError, OSError) as exc:
        Logger.get_logger().warning(f"Could not read SBOM file for upload validation: {exc}")
        return False


def upload_run(run: ScanRun, accuknox_config: dict, keep_results: bool, extra_params: dict | None) -> UploadOutcome:
    """Upload a scan result (the file is removed afterwards unless ``keep_results``)."""
    if is_empty_sbom(run):
        Logger.get_logger().warning("SBOM output is empty or missing components; skipping upload.")
        discard_result(run, keep_results)
        return UploadOutcome(empty_sbom=True)

    code = upload_results(
        run.result_file,
        accuknox_config["accuknox_endpoint"],
        accuknox_config["accuknox_label"],
        accuknox_config["accuknox_token"],
        accuknox_config["accuknox_tenant"],
        run.data_type,
        keep_file=keep_results,
        extra_params=extra_params,
    )
    return UploadOutcome(exit_code=code, uploaded=code == 0)


def gate_exit_code(run: ScanRun, uploaded: bool) -> int:
    """Scan exit code once the backend policy decides what a finding costs.

    A non-zero exit with a result that reached the backend means "findings" (opengrep, checkov, trivy
    and trufflehog all exit non-zero for them), which the policy now judges. Failures to run the scanner
    stay failures, as does SAST exit 2 (the scanner or its AI analysis failed).
    """
    if run.exit_code != 0 and uploaded and not (run.scantype.upper() == "SAST" and run.exit_code == 2):
        return 0
    return run.exit_code
