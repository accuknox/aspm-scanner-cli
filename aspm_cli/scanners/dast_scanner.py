import argparse
import os
from aspm_cli.scanners.base_scanner import BaseScanner
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.scan.dast import DASTScanner as OriginalDASTScanner, DAST_PLAN_CHOICES # Import original scanner logic

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
            help="Arguments to pass to the DAST scanner (e.g., 'zap-baseline.py -t https://example.com -I'). "
                 "Mutually exclusive with --plan."
        )
        parser.add_argument(
            "--plan",
            choices=DAST_PLAN_CHOICES,
            help="Run a predefined ZAP Automation Framework plan (baseline, standard, extended, comprehensive) "
                 "against --target-url instead of a raw --command."
        )
        parser.add_argument(
            "--target-url",
            help="Target URL to scan. Required when --plan is used."
        )
        parser.add_argument(
            "--container-mode",
            action="store_true",
            help="Run in container mode"
        )

        auth_group = parser.add_argument_group(
            "authenticated scan (--plan only)",
            "Set these to crawl as a logged-in user (form-based auth). Omit all of them for a "
            "non-auth scan, which is the default.",
        )
        auth_group.add_argument(
            "--auth-login-url",
            help="Login page URL. Presence of this flag (with --auth-username/--auth-password) "
                 "switches the scan to authenticated mode."
        )
        auth_group.add_argument(
            "--auth-login-request-url",
            help="Login form POST URL, if different from --auth-login-url."
        )
        auth_group.add_argument(
            "--auth-login-request-body",
            help="Login POST body template, e.g. 'username={%%username%%}&password={%%password%%}'. "
                 "Defaults to that."
        )
        auth_group.add_argument(
            "--auth-username",
            help="Username for the authenticated scan. Falls back to the DAST_AUTH_USERNAME env var."
        )
        auth_group.add_argument(
            "--auth-password",
            help="Password for the authenticated scan. Falls back to the DAST_AUTH_PASSWORD env var."
        )
        auth_group.add_argument(
            "--auth-logged-in-regex",
            help="Response regex indicating a logged-in session (auth verification)."
        )
        auth_group.add_argument(
            "--auth-logged-out-regex",
            help="Response regex indicating a logged-out session (auth verification)."
        )

    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        # Resolve secret fallbacks once so validation and run_scan agree on the effective values.
        args.auth_username = args.auth_username or os.getenv("DAST_AUTH_USERNAME")
        args.auth_password = args.auth_password or os.getenv("DAST_AUTH_PASSWORD")

        validator.validate_dast_scan(
            args.command,
            args.severity_threshold,
            args.container_mode,
            plan=args.plan,
            target_url=args.target_url,
            auth_login_url=args.auth_login_url,
            auth_username=args.auth_username,
            auth_password=args.auth_password,
        )

    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        scanner = OriginalDASTScanner(
            command=args.command or "",
            severity_threshold=args.severity_threshold,
            container_mode=args.container_mode,
            plan=args.plan,
            target_url=args.target_url,
            auth_login_url=args.auth_login_url,
            auth_login_request_url=args.auth_login_request_url,
            auth_login_request_body=args.auth_login_request_body,
            auth_username=args.auth_username,
            auth_password=args.auth_password,
            auth_logged_in_regex=args.auth_logged_in_regex,
            auth_logged_out_regex=args.auth_logged_out_regex,
        )
        return scanner.run()
