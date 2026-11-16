import argparse
import shlex
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.scan.dast import DASTScanner as OriginalDASTScanner # Import original scanner logic

SCRIPTS = {"baseline": "zap-baseline.py", "full": "zap-full-scan.py", "api": "zap-api-scan.py"}

class DASTScanner(BaseScanner):
    help_text = "Run a DAST scan"
    data_type_identifier = "ZAP"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--severity-threshold",
            default="HIGH",
            help="Severity level to fail the scan. Allowed values: LOW, MEDIUM, HIGH. Default is HIGH"
        )
        parser.add_argument(
            "--scan-type",
            choices=sorted(SCRIPTS),
            help="DAST scan type: baseline (passive), full (active) or api (OpenAPI/SOAP/GraphQL). "
                 "Required with --target."
        )
        parser.add_argument("--target", dest="dast_target", help="Target URL (or API definition file for --scan-type api)")
        parser.add_argument(
            "--options",
            default="",
            help="Extra scanner options, e.g. '-m 5' (spider minutes) or '-I' (don't fail on warnings)"
        )
        # Legacy raw-command flag, kept working but not advertised.
        parser.add_argument("--command", default="", help=argparse.SUPPRESS)
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode"
        )
        parser.add_argument(
            "--dast-plan",
            dest="zap_plan",
            metavar="PLAN",
            help="Path to a DAST automation plan (YAML) to run as-is instead of "
                 "--scan-type/--auth-* - full control over jobs (spiderAjax, activeScan, passive "
                 "rule config, auth or unauth)."
        )
        parser.add_argument("--zap-plan", dest="zap_plan", help=argparse.SUPPRESS)  # legacy alias
        parser.add_argument(
            "--auth-url",
            help="Login page URL, logged into with a real headless browser "
                 "(requires --auth-username and --auth-password)"
        )
        parser.add_argument(
            "--auth-username",
            help="Username for authenticated DAST scan"
        )
        parser.add_argument(
            "--auth-password",
            help="Password for authenticated DAST scan"
        )
        parser.add_argument(
            "--auth-logged-in-regex",
            help="Logged In Indicator - regex matched against a response to confirm login succeeded"
        )
        parser.add_argument(
            "--auth-logged-out-regex",
            help="Logged Out Indicator - regex matched against a response to confirm the session is unauthenticated"
        )
        parser.add_argument(
            "--auth-login-fallback-url",
            help="Login Fallback URL - post-login page used to verify a successful login "
                 "(e.g. a 'whoami' endpoint), polled instead of matching the indicator regexes "
                 "against every response"
        )

    @staticmethod
    def _command(args: argparse.Namespace) -> str:
        """Build the underlying scanner command from --scan-type/--target/--options (or legacy --command)."""
        if args.scan_type:
            if not args.dast_target:
                raise ValueError("--scan-type requires --target.")
            return shlex.join([SCRIPTS[args.scan_type], "-t", args.dast_target]) + f" {args.options}".rstrip()
        if args.dast_target:
            raise ValueError("--target requires --scan-type.")
        return args.command

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        args.command = self._command(args)
        validator.validate_dast_scan(
            args.command,
            args.severity_threshold,
            args.container_mode,
            auth_url=args.auth_url,
            auth_username=args.auth_username,
            auth_password=args.auth_password,
            zap_plan=args.zap_plan,
        )

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalDASTScanner(
            self._command(args),
            args.severity_threshold,
            args.container_mode,
            auth_url=args.auth_url,
            auth_username=args.auth_username,
            auth_password=args.auth_password,
            auth_logged_in_regex=args.auth_logged_in_regex,
            auth_logged_out_regex=args.auth_logged_out_regex,
            auth_login_fallback_url=args.auth_login_fallback_url,
            plan_file=args.zap_plan,
        )
        return scanner.run()