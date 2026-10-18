import os
import shutil
import sys
import tempfile

from pydantic import ValidationError

from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.commands.gate_command import add_gate_arguments
from aspm_cli.utils.common import handle_failure
from aspm_cli.utils.ingest_identity import collect_ingest_identity
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.quality_gate import (
    EXIT_OPERATIONAL,
    GateConfigError,
    decide,
    gate_upload_params,
    poll_gate,
    report,
    resolve_cli_id,
)
from aspm_cli.utils.scan_runner import (
    build_accuknox_config,
    discard_result,
    gate_exit_code,
    is_empty_sbom,
    run_scan,
    scanner_args,
    upload_run,
)

# --scans value -> (scanner registry key, scanner argv built from the pipeline options)
SCAN_BUILDERS = {
    "sast": ("SAST", lambda a: ["--command", a.sast_command]),
    "sq-sast": ("SQ-SAST", lambda a: ["--command", a.sq_sast_command]),
    "sca": ("SCA", lambda a: ["--command", a.sca_command]),
    "secret": ("SECRET", lambda a: ["--command", a.secret_command, "--engine", a.secret_engine]),
    "iac": ("IAC", lambda a: ["--command", a.iac_command]),
    "sbom": ("CONTAINER", lambda a: ["--command", a.sbom_command, "--generate-sbom"]),
}


# Scans that have an AI analysis step, and the scanner options --ai-analysis turns into for each.
# A scan type that gains AI analysis later is added here; the --ai-* options are shared.
AI_SCANS = {
    "sast": lambda a: ["--ai-analysis"]
    + (["--aiscan-severity", a.aiscan_severity] if a.aiscan_severity else [])
    + (["--codeassure-config", a.codeassure_config] if a.codeassure_config else [])
    + (["--context-graph-config", a.context_graph_config] if a.context_graph_config else [])
    + (["--graph-no-joern"] if a.graph_no_joern else []),
}


class PipelineCommand(BaseCommand):
    help_text = "Run several scans, upload them as one run and enforce the quality gate"

    def configure_parser(self, parser):
        parser.add_argument(
            "--scans",
            required=True,
            help=f"Comma-separated scans to run, in order: {', '.join(SCAN_BUILDERS)}.",
        )
        parser.add_argument("--endpoint", help="The URL of the Control Panel to push the scan results to.")
        parser.add_argument("--label", help="The label created in AccuKnox for associating scan results.")
        parser.add_argument("--token", help="The token for authenticating with the Control Panel.")
        parser.add_argument("--tenant", help="Tenant ID [Optional]")
        parser.add_argument("--project-name", dest="project_name", help="Project name - required for the sbom scan")
        parser.add_argument("--softfail", action="store_true", help="Do not fail the build on findings or a policy failure")
        parser.add_argument("--skip-upload", action="store_true", help="Run the scans without uploading (no quality gate)")
        parser.add_argument("--keep-results", action="store_true", help="Keep the result files after completion")
        parser.add_argument("--container-mode", action="store_true", help="Run the scanners in containers")
        parser.add_argument("--fail-fast", action="store_true", help="Stop at the first scan that fails to run")
        parser.add_argument(
            "--quality-gate",
            action="store_true",
            help="Let the policy thresholds in AccuKnox decide the build: wait for the verdict after uploading. "
            "Also enabled by ACCUKNOX_QUALITY_GATE=true.",
        )
        parser.add_argument("--cli-id", help="Run id (default: ACCUKNOX_CLI_ID, else derived from the CI run)")
        parser.add_argument("--repository", help="owner/name that policy scopes match (default: from the repository URL)")
        add_gate_arguments(parser)

        parser.add_argument(
            "--ai-analysis",
            action="store_true",
            help=f"Run AI analysis on the scans that support it ({', '.join(AI_SCANS)}). Off by default.",
        )
        parser.add_argument("--aiscan-severity", help="With --ai-analysis: only analyze findings of these severities (e.g. HIGH,CRITICAL)")
        parser.add_argument("--codeassure-config", help="With --ai-analysis: path to the codeassure.json model config")
        parser.add_argument("--context-graph-config", help="With --ai-analysis: path to context_graph.json")
        parser.add_argument("--graph-no-joern", action="store_true", help="With --ai-analysis: use tree-sitter graphs without Joern")

        parser.add_argument("--sast-command", default="scan .", help="SAST scanner arguments (default: 'scan .')")
        parser.add_argument("--sq-sast-command", help="SonarQube scanner arguments (required for sq-sast)")
        parser.add_argument("--sca-command", default="fs .", help="SCA (Trivy) arguments (default: 'fs .')")
        parser.add_argument("--secret-command", default="filesystem .", help="Secret scanner arguments (default: 'filesystem .')")
        parser.add_argument("--secret-engine", choices=["trufflehog", "gitleaks"], default="trufflehog")
        parser.add_argument("--iac-command", default="-d .", help="IaC scanner arguments (default: '-d .')")
        parser.add_argument("--sbom-command", default="filesystem .", help="SBOM arguments (default: 'filesystem .')")
        parser.set_defaults(func=self.execute)

    def execute(self, args):
        workdir = tempfile.mkdtemp(prefix="accuknox-pipeline-")
        try:
            sys.exit(self._run(args, workdir))
        except ValidationError as exc:
            Logger.get_logger().error(f"Configuration validation error: {exc}")
            sys.exit(1)
        except (GateConfigError, ValueError) as exc:
            Logger.get_logger().error(str(exc))
            sys.exit(EXIT_OPERATIONAL)
        finally:
            if args.keep_results:
                Logger.get_logger().info(f"Results kept in {workdir}")
            else:
                shutil.rmtree(workdir, ignore_errors=True)

    def _run(self, args, workdir) -> int:
        logger = Logger.get_logger()
        softfail = args.softfail or os.getenv("SOFT_FAIL") == "TRUE"
        quality_gate = args.quality_gate or os.getenv("ACCUKNOX_QUALITY_GATE", "").lower() in ("1", "true", "yes")
        if quality_gate and args.skip_upload:
            raise GateConfigError("--quality-gate needs the results uploaded; remove --skip-upload.")

        scans = list(dict.fromkeys(part.strip().lower() for part in args.scans.split(",") if part.strip()))
        unknown = [scan for scan in scans if scan not in SCAN_BUILDERS]
        if unknown or not scans:
            raise GateConfigError(f"Unknown scan(s): {', '.join(unknown) or '(none)'}. Available: {', '.join(SCAN_BUILDERS)}.")
        ai_options = [flag for flag, value in (
            ("--aiscan-severity", args.aiscan_severity), ("--codeassure-config", args.codeassure_config),
            ("--context-graph-config", args.context_graph_config), ("--graph-no-joern", args.graph_no_joern),
        ) if value]
        if ai_options and not args.ai_analysis:
            raise GateConfigError(f"{', '.join(ai_options)} only apply with --ai-analysis.")
        if args.ai_analysis and not any(scan in AI_SCANS for scan in scans):
            logger.warning(f"--ai-analysis has no effect: none of the selected scans support it ({', '.join(AI_SCANS)}).")
        if "sq-sast" in scans and not args.sq_sast_command:
            raise GateConfigError("--sq-sast-command is required for the sq-sast scan.")

        accuknox_config = build_accuknox_config(args)
        cli_id = resolve_cli_id(args.cli_id) if quality_gate else None

        # Phase 1: run every scan. A scan that cannot run is a failure of the build, not of the others.
        runs, broken = [], []
        for scan in scans:
            registry_key, build_argv = SCAN_BUILDERS[scan]
            argv = build_argv(args) + (["--container-mode"] if args.container_mode else [])
            if args.ai_analysis and scan in AI_SCANS:
                argv += AI_SCANS[scan](args)
            try:
                scan_args = scanner_args(registry_key, argv)
                run = run_scan(scan_args, accuknox_config, softfail, args.skip_upload)
            except (ValidationError, ValueError, OSError) as exc:
                logger.error(f"{scan} scan could not run: {exc}")
                broken.append(scan)
                if args.fail_fast:
                    break
                continue
            except Exception as exc:  # a scanner raising must not hide the other scans' results
                logger.error(f"{scan} scan failed: {exc}")
                broken.append(scan)
                if args.fail_fast:
                    break
                continue
            if run.result_file and os.path.exists(run.result_file):
                # Scanners share fixed file names (./results.json), so park each result before the next scan.
                parked = os.path.join(workdir, f"{scan}{os.path.splitext(run.result_file)[1]}")
                shutil.move(run.result_file, parked)
                run.result_file = parked
            else:
                logger.info(f"{scan}: no result produced, nothing to upload.")
            runs.append((scan, run))

        # Phase 2: upload, declaring to the gate exactly the scans that have something to evaluate.
        uploadable = []
        for scan, run in runs:
            if run.result_file and is_empty_sbom(run):
                logger.warning(f"{scan}: SBOM output is empty or missing components; nothing to upload.")
                discard_result(run, args.keep_results)
            elif run.result_file:
                uploadable.append((scan, run))
        uploaded = set()
        upload_failed = []
        if args.skip_upload:
            for _, run in uploadable:
                discard_result(run, args.keep_results)
        elif uploadable:
            declared = list(dict.fromkeys(run.data_type for _, run in uploadable))
            identity = collect_ingest_identity()
            if quality_gate:
                logger.info(f"Quality gate run id: {cli_id}")
            for scan, run in uploadable:
                params = gate_upload_params(cli_id, declared, identity, args.repository) if quality_gate else identity
                outcome = upload_run(run, accuknox_config, args.keep_results, params)
                if outcome.uploaded:
                    uploaded.add(scan)
                elif not outcome.empty_sbom:
                    upload_failed.append(scan)

        # Local outcome: with a quality gate the policy judges findings, otherwise the scanners' own exit codes do.
        operational = bool(broken or upload_failed)
        worst = 0
        for scan, run in runs:
            code = gate_exit_code(run, scan in uploaded) if quality_gate else run.exit_code
            if code != 0 and not (softfail and not (run.scantype.upper() == "SAST" and code == 2)):
                worst = max(worst, code)

        if not quality_gate:
            if operational:
                logger.error(f"Failed: {', '.join(broken + upload_failed)}.")
                return EXIT_OPERATIONAL
            handle_failure(worst, softfail=False, allow_softfail=False)
            return worst

        if upload_failed:
            logger.error(
                f"Upload failed for {', '.join(upload_failed)}; the quality gate would wait for it, so it is not polled."
            )
            return EXIT_OPERATIONAL
        if not uploaded:
            logger.info("No scan produced results, so there is nothing for the quality gate to evaluate.")
            return EXIT_OPERATIONAL if operational else worst

        # Phase 3: the verdict.
        logger.info(f"Waiting up to {args.gate_timeout}s for the quality gate...")
        gate_config = {**accuknox_config, "accuknox_gate_token": args.gate_token or os.getenv("ACCUKNOX_GATE_TOKEN")}
        result = poll_gate(gate_config, cli_id, timeout=args.gate_timeout)
        gate_code = decide(result, softfail, args.gate_on_timeout)
        report(result, gate_code, softfail, cli_id=cli_id, json_file=args.gate_json_file or os.getenv("ACCUKNOX_GATE_JSON_FILE"))
        if broken:
            logger.error(f"These scans could not run, so the build fails regardless of the gate: {', '.join(broken)}.")
            return EXIT_OPERATIONAL
        return max(gate_code, worst)
