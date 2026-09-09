import subprocess
import json
import os
import shlex
import importlib.resources as importlib_resources

from colorama import Fore
from aspm_cli.utils import config, docker_pull
from aspm_cli.utils.docker_runtime import build_docker_run_prefix
from aspm_cli.utils.logger import Logger
from aspm_cli.tool.manager import ToolManager

# Predefined ZAP Automation Framework scan plans, bundled under aspm_cli/dast_plans/.
DAST_PLAN_CHOICES = ("baseline", "standard", "extended", "comprehensive")
_DAST_PLAN_TARGET_PLACEHOLDER = "__TARGET_URL__"
_DAST_PLAN_AUTH_CONTEXT_PLACEHOLDER = "__AUTH_CONTEXT_BLOCK__"
_DAST_PLAN_SPIDER_USER_PLACEHOLDER = "__SPIDER_USER__"
_DAST_PLAN_FILE_NAME = "dast-plan.yaml"
_DAST_AUTH_USER_NAME = "dast-auth-user"

class DASTScanner:
    zap_image = os.getenv("SCAN_IMAGE", "public.ecr.aws/k9v9d5v2/zaproxy/zap-stable:2.16.1")
    result_file = "results.json"

    def __init__(
        self,
        command="",
        severity_threshold=None,
        container_mode=True,
        plan=None,
        target_url=None,
        auth_login_url=None,
        auth_login_request_url=None,
        auth_login_request_body=None,
        auth_username=None,
        auth_password=None,
        auth_logged_in_regex=None,
        auth_logged_out_regex=None,
    ):
        """
        :param command: Raw CLI args string for zap scripts
                        Example: "zap-baseline.py -t https://example.com -J results.json -I"
        :param severity_threshold: Minimum severity to fail on ("High", "Medium", "Low", "Informational")
        :param container_mode: Currently only container mode is supported
        :param plan: Name of a predefined scan plan (baseline, standard, extended, comprehensive).
                     When set, runs `zap.sh -cmd -autorun` against the plan instead of `command`.
        :param target_url: Target URL to scan, required when `plan` is set.
        :param auth_login_url: Login page URL. When set (with auth_username/auth_password), the
                        rendered plan crawls as an authenticated user (form-based auth) instead of
                        anonymously. Leave unset for a non-auth scan.
        :param auth_login_request_url: Login POST URL, if different from auth_login_url.
        :param auth_login_request_body: Login POST body template, e.g.
                        "username={%username%}&password={%password%}".
        :param auth_username: Username for the authenticated scan.
        :param auth_password: Password for the authenticated scan.
        :param auth_logged_in_regex: Response regex indicating a logged-in session.
        :param auth_logged_out_regex: Response regex indicating a logged-out session.
        """
        self.command = command
        self.severity_threshold = severity_threshold
        self.container_mode = container_mode
        self.plan = plan
        self.target_url = target_url
        self.auth_login_url = auth_login_url
        self.auth_login_request_url = auth_login_request_url
        self.auth_login_request_body = auth_login_request_body
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.auth_logged_in_regex = auth_logged_in_regex
        self.auth_logged_out_regex = auth_logged_out_regex

    @property
    def is_authenticated(self):
        return bool(self.auth_login_url and self.auth_username and self.auth_password)

    def run(self):
        plan_file_path = None
        try:
            if self.container_mode:
                docker_pull(self.zap_image)
                Logger.get_logger().debug("Starting DAST scan...")

            if self.plan:
                plan_file_path = self._render_plan_file()
                # zap.sh's -autorun does not resolve a bare relative filename against
                # the container's --workdir; it needs the absolute in-container path.
                plan_arg = f"/zap/wrk/{os.path.basename(plan_file_path)}" if self.container_mode else plan_file_path
                args = ["zap.sh", "-cmd", "-autorun", plan_arg]
            else:
                args = self._build_dast_args()
            cmd, env = self._build_dast_command(args)

            Logger.get_logger().debug(f"Running DAST scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)

            if result.stdout:
                Logger.get_logger().debug(result.stdout)
            if result.stderr:
                Logger.get_logger().error(result.stderr)

            if result.stdout:
                sanitized_stdout = result.stdout ##.replace("zap", "[scanner]")
                Logger.get_logger().debug(sanitized_stdout)
                if(not self.plan and "-help" in self.command):
                    Logger.log_with_color('INFO', sanitized_stdout, Fore.WHITE)
                    return config.PASS_RETURN_CODE, None
            if result.stderr:
                sanitized_stderr = result.stderr ##.replace("zap", "[scanner]")
                Logger.get_logger().error(sanitized_stderr)

            if not os.path.exists(self.result_file):
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

            exit_code = self.evaluate_results()
            return exit_code, self.result_file if os.path.exists(self.result_file) else None

        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during DAST scan: {e}")
            raise
        finally:
            if plan_file_path and os.path.exists(plan_file_path):
                os.remove(plan_file_path)

    def _render_plan_file(self):
        """
        Render the selected predefined plan (target URL, and optionally form-based
        auth, substituted in) to a file in the current working directory, which is
        bind-mounted into the ZAP container (or is the local zap.sh working directory).
        """
        if self.plan not in DAST_PLAN_CHOICES:
            raise ValueError(f"Unknown DAST plan '{self.plan}'. Allowed values: {', '.join(DAST_PLAN_CHOICES)}")
        if not self.target_url:
            raise ValueError("target_url is required when using a DAST plan")

        plan_text = (
            importlib_resources.files("aspm_cli.dast_plans")
            .joinpath(f"{self.plan}.yaml")
            .read_text(encoding="utf-8")
        )
        rendered = plan_text.replace(_DAST_PLAN_TARGET_PLACEHOLDER, self.target_url)

        if self.is_authenticated:
            Logger.get_logger().debug(f"DAST plan '{self.plan}': running as authenticated user.")
            auth_block = self._build_auth_context_block()
            spider_user_line = f'    user: "{_DAST_AUTH_USER_NAME}"'
        else:
            auth_block = ""
            spider_user_line = ""
        rendered = rendered.replace(_DAST_PLAN_AUTH_CONTEXT_PLACEHOLDER, auth_block)
        rendered = rendered.replace(_DAST_PLAN_SPIDER_USER_PLACEHOLDER, spider_user_line)

        plan_file_path = os.path.join(os.getcwd(), _DAST_PLAN_FILE_NAME)
        with open(plan_file_path, "w", encoding="utf-8") as f:
            f.write(rendered)
        return plan_file_path

    def _build_auth_context_block(self):
        """
        Build the `authentication`/`sessionManagement`/`users` YAML block (form-based
        auth) inserted into the target-context, indented to match its siblings (urls,
        includePaths).
        """
        def esc(value):
            return value.replace("\\", "\\\\").replace('"', '\\"')

        login_url = esc(self.auth_login_url)
        login_request_url = esc(self.auth_login_request_url or self.auth_login_url)
        login_request_body = esc(
            self.auth_login_request_body or "username={%username%}&password={%password%}"
        )

        verification_lines = ['        method: "response"']
        if self.auth_logged_in_regex:
            verification_lines.append(f'        loggedInRegex: "{esc(self.auth_logged_in_regex)}"')
        if self.auth_logged_out_regex:
            verification_lines.append(f'        loggedOutRegex: "{esc(self.auth_logged_out_regex)}"')
        if not self.auth_logged_in_regex and not self.auth_logged_out_regex:
            Logger.get_logger().warning(
                "Authenticated DAST scan configured without --auth-logged-in-regex or "
                "--auth-logged-out-regex; ZAP may not reliably detect login state."
            )

        lines = [
            "    authentication:",
            '      method: "form"',
            "      parameters:",
            f'        loginPageUrl: "{login_url}"',
            f'        loginRequestUrl: "{login_request_url}"',
            f'        loginRequestBody: "{login_request_body}"',
            "      verification:",
            *verification_lines,
            "    sessionManagement:",
            '      method: "cookie"',
            "    users:",
            f'    - name: "{_DAST_AUTH_USER_NAME}"',
            "      credentials:",
            f'        username: "{esc(self.auth_username)}"',
            f'        password: "{esc(self.auth_password)}"',
        ]
        return "\n".join(lines)

    def _build_dast_args(self):
        """
        Sanitize the raw command, remove conflicting report flags,
        and enforce JSON output.
        """
        args = shlex.split(self.command)

        if not self.container_mode and ("zap-baseline.py" in shlex.join(args) or "zap-full-scan.py" in shlex.join(args)):
            raise NotImplementedError(
                "DASTScanner currently supports zap.sh only"
            )

        # ZAP conflicting report flags
        forbidden_flags = []
        if "zap-baseline.py" in shlex.join(args) or "zap-full-scan.py" in shlex.join(args):
            forbidden_flags = {"-r", "-w", "-x", "-J"}

        sanitized_args = []
        i = 0
        while i < len(args):
            if args[i] in forbidden_flags:
                # Skip the flag and its value
                i += 2
                continue
            sanitized_args.append(args[i])
            i += 1

        if "zap-baseline.py" in shlex.join(args) or "zap-full-scan.py" in shlex.join(args):
            # Always enforce JSON report at results.json
            sanitized_args.extend([
                "-J", os.path.basename(self.result_file)
            ])

        return sanitized_args

    def _build_dast_command(self, args):
        env = os.environ.copy()

        if not self.container_mode:
            first_arg = os.path.join(ToolManager.get_path("dast"), args[0])
            cmd = [first_arg]

            cmd.extend(args[1:])
            java_home = ToolManager.get_path("dast-java")
            env = os.environ.copy()
            env["JAVA_HOME"] = java_home
            env["PATH"] = java_home + os.pathsep + env.get("PATH", "")
        else:
            cmd = build_docker_run_prefix(workdir="/zap/wrk")
            cmd.extend(["-t", self.zap_image])
            cmd.extend(args)
        return cmd, env

    def evaluate_results(self):
        """
        Parse ZAP JSON report and check alerts against severity threshold.
        """
        risk_map = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        threshold = self.severity_threshold.strip().upper()
        risk_code = risk_map.get(threshold)

        try:
            with open(self.result_file, "r") as f:
                zap_results = json.load(f)

            alerts = [
                alert for site in zap_results.get("site", [])
                for alert in site.get("alerts", [])
                if int(alert["riskcode"]) >= risk_code
            ]

            if alerts:
                Logger.get_logger().error(
                    f"Found vulnerabilities with severity {threshold} or higher."
                )
                return 1
            else:
                Logger.get_logger().info(
                    f"No vulnerabilities with severity {threshold} or higher found."
                )
                return 0

        except Exception as e:
            Logger.get_logger().error(f"Error evaluating DAST results: {e}")
            return 1
