import os
import sys
from pydantic import ValidationError

from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.scanners import scanner_registry
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.spinner import Spinner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.common import upload_results, handle_failure, ALLOWED_SCAN_TYPES
from aspm_cli.utils.git_info import GitInfo

class ScanCommand(BaseCommand):
    help_text = f"Run a security scan (e.g. {', '.join(ALLOWED_SCAN_TYPES)})"

    def configure_parser(self, parser):
        subparsers = parser.add_subparsers(dest="scantype")

        parser.add_argument("--endpoint", help="The URL of the Control Panel to push the scan results to.")
        parser.add_argument("--label", help="The label created in AccuKnox for associating scan results.")
        parser.add_argument("--token", help="The token for authenticating with the Control Panel.")
        parser.add_argument('--softfail', action='store_true', help='Enable soft fail mode for scanning')
        parser.add_argument('--skip-upload', action='store_true', help='Skip control plane upload')

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

            accuknox_config = {
                "accuknox_endpoint": args.endpoint or os.getenv("ACCUKNOX_ENDPOINT"),
                "accuknox_label": args.label or os.getenv("ACCUKNOX_LABEL"),
                "accuknox_token": args.token or os.getenv("ACCUKNOX_TOKEN")
            }

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
            if not skip_upload and result_file:
                upload_exit_code = upload_results(result_file, accuknox_config["accuknox_endpoint"], accuknox_config["accuknox_label"], accuknox_config["accuknox_token"], scanner.data_type_identifier)
            elif result_file and os.path.exists(result_file):
                os.remove(result_file)
            else:
                pass # No result file or skip upload, nothing to do with it
            handle_failure(exit_code if exit_code != 0 else upload_exit_code, softfail)

        except ValidationError as e:
            Logger.get_logger().error(f"Configuration validation error: {e}")
            sys.exit(1)
        except Exception as e:
            Logger.get_logger().error("Scan failed.")
            Logger.get_logger().error(e)
            sys.exit(1)