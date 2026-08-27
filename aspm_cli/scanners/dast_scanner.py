import argparse
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.scan.dast import DASTScanner as OriginalDASTScanner # Import original scanner logic

class DASTScanner(BaseScanner):
    help_text = "Run a DAST scan using OWASP ZAP"
    data_type_identifier = "ZAP"

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--severity-threshold",
            default="HIGH",
            help="Severity level to fail the scan. Allowed values: LOW, MEDIUM, HIGH. Default is HIGH"
        )
        parser.add_argument(
            "--command",
            default="",
            help="Arguments to pass to the DAST scanner (e.g., 'zap-baseline.py -t https://example.com -I'). "
                 "Required unless --zap-plan is given."
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode"
        )
        parser.add_argument(
            "--zap-plan",
            help="Path to a ZAP Automation Framework plan (zap.yaml) to run as-is instead of "
                 "--command/--auth-* - full control over jobs (spiderAjax, activeScan, passive "
                 "rule config, auth or unauth). See https://www.zaproxy.org/docs/automate/automation-framework/"
        )
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

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
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
            args.command,
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