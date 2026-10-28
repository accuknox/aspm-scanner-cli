import os
import sys
from pydantic import ValidationError

from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.scanners import scanner_registry
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.common import handle_failure, ALLOWED_SCAN_TYPES
from aspm_cli.utils.ingest_identity import collect_ingest_identity
from aspm_cli.utils.quality_gate import (
    EXIT_OPERATIONAL,
    GATE_SCANNERS,
    GateConfigError,
    gate_upload_params,
    normalize_scanners,
    resolve_cli_id,
)
from aspm_cli.utils.scan_runner import (
    UploadOutcome,
    build_accuknox_config,
    discard_result,
    gate_exit_code,
    run_scan,
    upload_run,
)

class ScanCommand(BaseCommand):
    help_text = f"Run a security scan (e.g. {', '.join(ALLOWED_SCAN_TYPES)})"

    def configure_parser(self, parser):
        subparsers = parser.add_subparsers(dest="scantype")

        parser.add_argument("--endpoint", help="The URL of the Control Panel to push the scan results to.")
        parser.add_argument("--label", help="The label created in AccuKnox for associating scan results.")
        parser.add_argument("--token", help="The token for authenticating with the Control Panel.")
        parser.add_argument("--tenant", help="Tenant ID [Optional]")
        parser.add_argument(
            "--project-name",
            dest="project_name",
            help="Project name (AccuKnox entity) - Required for SBOM uploads",
        )
        parser.add_argument('--softfail', action='store_true', help='Enable soft fail mode for scanning')
        parser.add_argument('--skip-upload', action='store_true', help='Skip control plane upload')
        parser.add_argument('--keep-results', action='store_true', help='Keep scan results file after completion')
        parser.add_argument(
            "--quality-gate",
            action="store_true",
            help=(
                "Tie this upload to a quality-gate run so policy thresholds decide the build. Findings no longer "
                "fail this step; run `accuknox-aspm-scanner gate` after all scans (or use `pipeline`). "
                "Also enabled by ACCUKNOX_QUALITY_GATE=true."
            ),
        )
        parser.add_argument(
            "--gate-scanners",
            help=f"Quality gate: every scan type this run uploads, e.g. SG,TR,IAC (of {', '.join(GATE_SCANNERS)}).",
        )
        parser.add_argument(
            "--cli-id",
            help="Quality gate: run id shared by all steps (default: ACCUKNOX_CLI_ID, else derived from the CI run).",
        )
        parser.add_argument(
            "--repository",
            help="Quality gate: owner/name that policy scopes match (default: derived from the repository URL).",
        )

        # Dynamically add subparsers for each registered scanner
        for scan_type, scanner_class in scanner_registry.items():
            scanner_instance = scanner_class() # Create instance to get help_text
            scan_parser = subparsers.add_parser(scan_type.lower(), help=scanner_instance.help_text)
            scanner_instance.add_arguments(scan_parser)
            scan_parser.set_defaults(func=self.execute, scantype=scan_type) # Set scantype and func for main execute

    def execute(self, args):
        try:
            softfail = args.softfail or os.getenv("SOFT_FAIL") == "TRUE"
            skip_upload = args.skip_upload
            keep_results = args.keep_results or os.getenv("KEEP_RESULTS") == "TRUE"
            quality_gate = args.quality_gate or os.getenv("ACCUKNOX_QUALITY_GATE", "").lower() in ("1", "true", "yes")

            accuknox_config = build_accuknox_config(args)

            if getattr(args, "target", None) or args.scantype.upper() in {"SBOM", "MOBILE"}:
                if quality_gate:
                    raise GateConfigError(
                        "The quality gate does not cover artifact/mobile scans; use sast, sq-sast, sca, secret, iac "
                        "or `container --generate-sbom`."
                    )
                from aspm_cli.scan.artifact import execute_artifact
                from aspm_cli.utils.artifact_engine import ArtifactError
                try:
                    code = execute_artifact(args, accuknox_config, softfail)
                except (ArtifactError, OSError, ValueError) as exc:
                    Logger.get_logger().error(str(exc))
                    code = 2
                raise SystemExit(code)

            # Get the correct scanner strategy from the registry
            scantype_key = args.scantype
            if scantype_key not in scanner_registry:
                Logger.get_logger().error(f"Invalid scan type: {scantype_key}. Allowed types: {', '.join(scanner_registry.keys())}")
                sys.exit(1)

            if quality_gate:
                if skip_upload:
                    raise GateConfigError("--quality-gate needs the results uploaded; remove --skip-upload.")
                declared = normalize_scanners(args.gate_scanners or os.getenv("ACCUKNOX_GATE_SCANNERS") or "")
                cli_id = resolve_cli_id(args.cli_id)

            run = run_scan(args, accuknox_config, softfail, skip_upload)

            # Upload results and handle failure
            outcome = UploadOutcome()
            if run.result_file and os.path.exists(run.result_file):
                if skip_upload:
                    discard_result(run, keep_results)
                else:
                    extra_params = collect_ingest_identity()
                    if quality_gate:
                        if run.data_type not in declared:
                            declared.append(run.data_type)
                        extra_params = gate_upload_params(cli_id, declared, extra_params, args.repository)
                        Logger.get_logger().info(f"Quality gate run id: {cli_id}")
                    outcome = upload_run(run, accuknox_config, keep_results, extra_params)
                    if outcome.empty_sbom:
                        if quality_gate:
                            Logger.get_logger().warning(
                                "The SBOM was empty and not uploaded, so the gate will keep waiting for it. "
                                "Remove SBOM from --gate-scanners."
                            )
                        Logger.get_logger().debug(
                            f"Scan exit_code={run.exit_code}, upload_exit_code=0, "
                            f"softfail={softfail}, skip_upload={skip_upload}, keep_results={keep_results}"
                        )
                        handle_failure(run.exit_code, softfail, allow_softfail=True)
                        return
            elif quality_gate:
                Logger.get_logger().warning(
                    f"The {run.data_type} scan produced no result to upload, so the gate will keep waiting for it. "
                    "Remove it from --gate-scanners, or use `pipeline`, which declares only the scans that ran."
                )
            upload_exit_code = outcome.exit_code
            Logger.get_logger().debug(
                f"Scan exit_code={run.exit_code}, upload_exit_code={upload_exit_code}, softfail={softfail}, skip_upload={skip_upload}, keep_results={keep_results}"
            )
            if upload_exit_code != 0:
                # Upload issues should always fail the workflow; softfail applies only to findings
                handle_failure(upload_exit_code, softfail=False, allow_softfail=False)
            else:
                exit_code = gate_exit_code(run, outcome.uploaded) if quality_gate else run.exit_code
                handle_failure(exit_code, softfail, allow_softfail=not (args.scantype.lower() == "sast" and exit_code == 2))

        except ValidationError as e:
            Logger.get_logger().error(f"Configuration validation error: {e}")
            sys.exit(1)
        except GateConfigError as e:
            Logger.get_logger().error(str(e))
            sys.exit(EXIT_OPERATIONAL)
        except Exception as e:
            Logger.get_logger().error("Scan failed.")
            Logger.get_logger().error(e)
            sys.exit(1)
