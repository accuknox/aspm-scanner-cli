import os
import sys
import json
from pydantic import ValidationError

from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.scanners import scanner_registry
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.spinner import Spinner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.common import upload_results, handle_failure, ALLOWED_SCAN_TYPES
from aspm_cli.utils.git_info import GitInfo
from aspm_cli.utils.sbom import (
    derive_sbom_classifier,
    enrich_sbom_payload,
    is_sbom_payload_empty,
    resolve_project_name,
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
        # CI/CD quality-gate correlation. Every value is PASSED IN by the pipeline
        # — the CLI does no detection. The workflow generates one cli_id (shared by
        # all scanners) and passes the gate scope (repository/branch/commit). These
        # use distinct dests (gate_*) so they are NOT clobbered by the per-scanner
        # subparser defaults for --branch/--commit-sha.
        parser.add_argument('--cli-id', dest='cli_id',
                            help='CI/CD quality-gate run id (uuid) shared by all scanners in a '
                                 'pipeline run. Falls back to ACCUKNOX_CLI_ID. Only stamped onto '
                                 'uploads whose scanner prefix supports quality gates.')
        parser.add_argument('--repository', dest='gate_repository',
                            help='CI/CD gate scope repository (e.g. org/repo), passed by the pipeline.')
        parser.add_argument('--branch', dest='gate_branch',
                            help='CI/CD gate scope branch, passed by the pipeline.')
        parser.add_argument('--commit-sha', dest='gate_commit_sha',
                            help='CI/CD gate scope commit SHA, passed by the pipeline.')

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

            accuknox_config = {
                "accuknox_endpoint": args.endpoint or os.getenv("ACCUKNOX_ENDPOINT"),
                "accuknox_label": args.label or os.getenv("ACCUKNOX_LABEL"),
                "accuknox_token": args.token or os.getenv("ACCUKNOX_TOKEN"),
                "accuknox_tenant": args.tenant or os.getenv("ACCUKNOX_TENANT"),
                "accuknox_project_name": resolve_project_name(args.project_name),
            }

            # CI/CD quality-gate correlation, entirely passed in by the pipeline
            # (no detection here). When cli_id is set, upload_results stamps these
            # onto the upload ONLY for gate-supported scanner prefixes.
            cli_id = (args.cli_id or os.getenv("ACCUKNOX_CLI_ID") or "").strip() or None
            repository = (args.gate_repository or "").strip() or None
            branch = (args.gate_branch or "").strip() or None
            commit_sha = (args.gate_commit_sha or "").strip() or None

            # Get the correct scanner strategy from the registry
            scantype_key = args.scantype
            if scantype_key not in scanner_registry:
                Logger.get_logger().error(f"Invalid scan type: {scantype_key}. Allowed types: {', '.join(scanner_registry.keys())}")
                sys.exit(1)

            scanner = scanner_registry[scantype_key]() # Instantiate the scanner strategy

            # Validate configurations using the ConfigValidator
            validator = ConfigValidator(args.scantype.lower(), **accuknox_config, softfail=softfail, skip_upload=skip_upload)
            
            scanner.validate_config(args, validator)

            # Run scan with spinner
            spinner = Spinner(message=f"Running {args.scantype.lower()} scan...")
            
            spinner.start()
            
            exit_code, result_file = scanner.run_scan(args)
            spinner.stop()

            # Upload results and handle failure
            upload_exit_code = 0
            if result_file and os.path.exists(result_file):
                # Check if this is SBOM mode (container scan with --generate-sbom)
                is_sbom_upload = (
                    args.scantype.lower() == "container"
                    and getattr(args, "generate_sbom", False)
                )

                # If this is an SBOM upload, enrich the SBOM file with project_name and classifier
                if is_sbom_upload:
                    project_name = accuknox_config.get("accuknox_project_name")
                    scan_command = getattr(args, "command", "") or ""
                    project_classifier = derive_sbom_classifier(scan_command)
                    try:
                        with open(result_file, "r", encoding="utf-8") as f:
                            data = json.load(f)

                        if isinstance(data, dict):
                            enrich_sbom_payload(
                                data,
                                scan_command,
                                project_name,
                                project_classifier,
                            )

                            with open(result_file, "w", encoding="utf-8") as f:
                                json.dump(data, f, indent=2)
                    except Exception as e:
                        Logger.get_logger().debug(
                            f"Failed to enrich SBOM results.json: {e}"
                        )

                # Upload if not skipping
                if not skip_upload:
                    if is_sbom_upload:
                        try:
                            with open(result_file, "r", encoding="utf-8") as f:
                                sbom_data = json.load(f)
                            if is_sbom_payload_empty(sbom_data):
                                Logger.get_logger().warning(
                                    "SBOM output is empty or missing components; skipping upload."
                                )
                                if not keep_results:
                                    os.remove(result_file)
                                else:
                                    Logger.get_logger().info(f"Results file kept at: {result_file}")
                                upload_exit_code = 0
                                Logger.get_logger().debug(
                                    f"Scan exit_code={exit_code}, upload_exit_code={upload_exit_code}, "
                                    f"softfail={softfail}, skip_upload={skip_upload}, keep_results={keep_results}"
                                )
                                handle_failure(exit_code, softfail, allow_softfail=True)
                                return
                        except (json.JSONDecodeError, OSError) as e:
                            Logger.get_logger().warning(
                                f"Could not read SBOM file for upload validation: {e}"
                            )

                    # Determine data_type: SBOM for SBOM uploads, otherwise use scanner's identifier
                    data_type = "SBOM" if is_sbom_upload else scanner.get_data_type_identifier()
                    upload_exit_code = upload_results(
                        result_file,
                        accuknox_config["accuknox_endpoint"],
                        accuknox_config["accuknox_label"],
                        accuknox_config["accuknox_token"],
                        accuknox_config["accuknox_tenant"],
                        data_type,
                        keep_file=keep_results,
                        cli_id=cli_id,
                        repository=repository,
                        branch=branch,
                        commit_sha=commit_sha,
                    )
                else:
                    # Clean up result file when skipping upload (unless --keep-results is set)
                    if not keep_results:
                        os.remove(result_file)
                    else:
                        Logger.get_logger().info(f"Results file kept at: {result_file}")
            Logger.get_logger().debug(
                f"Scan exit_code={exit_code}, upload_exit_code={upload_exit_code}, softfail={softfail}, skip_upload={skip_upload}, keep_results={keep_results}"
            )
            if upload_exit_code != 0:
                # Upload issues should always fail the workflow; softfail applies only to findings
                handle_failure(upload_exit_code, softfail=False, allow_softfail=False)
            else:
                handle_failure(exit_code, softfail, allow_softfail=True)

        except ValidationError as e:
            Logger.get_logger().error(f"Configuration validation error: {e}")
            sys.exit(1)
        except Exception as e:
            Logger.get_logger().error("Scan failed.")
            Logger.get_logger().error(e)
            sys.exit(1)
