import subprocess
import json
import os
import shlex

import yaml
from colorama import Fore
from aspm_cli.utils import config, docker_pull
from aspm_cli.utils.docker_runtime import build_docker_run_prefix
from aspm_cli.utils.logger import Logger
from aspm_cli.tool.manager import ToolManager

class DASTScanner:
    zap_image = os.getenv("SCAN_IMAGE", "public.ecr.aws/k9v9d5v2/zaproxy/zap-stable:2.16.1")
    result_file = "results.json"
    auth_plan_file = "zap-automation-plan.yaml"
    container_workdir = "/zap/wrk"
    context_name = "auth-context"
    user_name = "auth-user"

    def __init__(
        self,
        command="",
        severity_threshold=None,
        container_mode=True,
        auth_url=None,
        auth_username=None,
        auth_password=None,
        auth_logged_in_regex=None,
        auth_logged_out_regex=None,
        auth_login_fallback_url=None,
        plan_file=None,
    ):
        """
        :param command: Raw CLI args string for zap scripts, e.g. "zap-baseline.py -t <url> -I"
        :param severity_threshold: Minimum severity to fail on (LOW/MEDIUM/HIGH)
        :param container_mode: Currently only container mode is supported
        :param auth_url: Login page URL for browser-based authentication
        :param auth_username: Username for the authenticated scan
        :param auth_password: Password for the authenticated scan
        :param auth_logged_in_regex: Logged In Indicator regex
        :param auth_logged_out_regex: Logged Out Indicator regex
        :param auth_login_fallback_url: Login Fallback URL polled to verify a successful login
        :param plan_file: Path to a user-supplied ZAP Automation Framework plan (zap.yaml)
        """
        self.command = command
        self.severity_threshold = severity_threshold
        self.container_mode = container_mode
        self.auth_url = auth_url
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.auth_logged_in_regex = auth_logged_in_regex
        self.auth_logged_out_regex = auth_logged_out_regex
        self.auth_login_fallback_url = auth_login_fallback_url
        self.plan_file = plan_file

    @property
    def auth_enabled(self):
        return bool(self.auth_url and self.auth_username and self.auth_password)

    def _extract_target(self, args):
        if "-t" in args:
            return args[args.index("-t") + 1]
        raise ValueError("DAST command must include '-t <target-url>'")

    def _extract_spider_minutes(self, args):
        if "-m" in args:
            return int(args[args.index("-m") + 1])
        return 1  # ponytail: matches zap-baseline.py's own default

    def _auth_method(self):
        authentication = {
            "method": "browser",
            "parameters": {
                "loginPageUrl": self.auth_url,
                "browserId": "firefox-headless",
                "loginPageWait": 5,
            },
        }
        if self.auth_logged_in_regex or self.auth_logged_out_regex:
            verification = {}
            if self.auth_logged_in_regex:
                verification["loggedInRegex"] = self.auth_logged_in_regex
            if self.auth_logged_out_regex:
                verification["loggedOutRegex"] = self.auth_logged_out_regex
            if self.auth_login_fallback_url:
                verification.update(method="poll", pollUrl=self.auth_login_fallback_url, pollFrequency=60, pollUnits="requests")
            else:
                verification["method"] = "response"
            authentication["verification"] = verification
        return authentication

    def _build_auth_plan(self, args, full_scan):
        """Build a ZAP Automation Framework plan using browser-based authentication."""
        target = self._extract_target(args)

        context = {
            "name": self.context_name,
            "urls": [target],
            "includePaths": [".*"],
            "authentication": self._auth_method(),
            "sessionManagement": {"method": "cookie"},
            "users": [{
                "name": self.user_name,
                "credentials": {"username": self.auth_username, "password": self.auth_password},
            }],
        }

        jobs = [
            {
                "type": "spider",
                "parameters": {
                    "context": self.context_name,
                    "user": self.user_name,
                    "url": target,
                    "maxDuration": self._extract_spider_minutes(args),
                },
            },
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
        ]
        if full_scan:
            jobs.append({"type": "activeScan", "parameters": {"context": self.context_name, "user": self.user_name}})
        jobs.append(self._report_job())

        return {
            "env": {
                "contexts": [context],
                "parameters": {"failOnError": True, "progressToStdout": True},
            },
            "jobs": jobs,
        }

    def _report_job(self):
        return {
            "type": "report",
            "parameters": {
                "template": "traditional-json",
                "reportDir": self.container_workdir,
                "reportFile": os.path.splitext(self.result_file)[0],
            },
        }

    def _write_auth_plan(self, args, full_scan):
        plan = self._build_auth_plan(args, full_scan)
        with open(self.auth_plan_file, "w") as f:
            yaml.safe_dump(plan, f, sort_keys=False)

    def _write_user_plan(self):
        """Load the user-supplied plan, swap in our own report job, write it for the container to mount."""
        with open(self.plan_file, "r") as f:
            plan = yaml.safe_load(f)
        if not isinstance(plan, dict) or "jobs" not in plan:
            raise ValueError(f"'{self.plan_file}' does not look like a ZAP automation plan (missing top-level 'jobs')")
        plan["jobs"] = [job for job in plan["jobs"] if job.get("type") != "report"]
        plan["jobs"].append(self._report_job())
        with open(self.auth_plan_file, "w") as f:
            yaml.safe_dump(plan, f, sort_keys=False)

    def _automation_command(self):
        cmd = build_docker_run_prefix(workdir=self.container_workdir)
        cmd.extend(["-t", self.zap_image])
        cmd.extend(["zap.sh", "-cmd", "-autorun", f"{self.container_workdir}/{self.auth_plan_file}"])
        return cmd

    def _check_automation_supported(self, is_baseline_or_full):
        """Raise if --auth-*/--zap-plan were given a command/mode combo that can't use them."""
        if self.auth_enabled and self.plan_file:
            raise ValueError("Use either --zap-plan or --auth-url/--auth-username/--auth-password, not both.")
        if self.auth_enabled and not self.plan_file and not is_baseline_or_full:
            raise ValueError(
                "DAST authentication (--auth-url/--auth-username/--auth-password) requires "
                "zap-baseline.py or zap-full-scan.py"
            )
        uses_automation = bool(self.plan_file) or self.auth_enabled
        if uses_automation and not self.container_mode:
            raise NotImplementedError(
                "--zap-plan and --auth-* require --container-mode (the automation framework needs "
                "zap.sh, and browser-based auth needs the headless Firefox/geckodriver bundled in "
                "the ZAP docker image)."
            )

    def run(self):
        try:
            args = shlex.split(self.command) if self.command else []
            joined = shlex.join(args)
            is_baseline_or_full = "zap-baseline.py" in joined or "zap-full-scan.py" in joined
            is_recognized_script = is_baseline_or_full or "zap-api-scan.py" in joined
            self._check_automation_supported(is_baseline_or_full)

            if self.container_mode:
                docker_pull(self.zap_image)
                Logger.get_logger().debug("Starting DAST scan...")

            if self.plan_file:
                Logger.get_logger().debug(f"DAST scan: running user-supplied ZAP plan '{self.plan_file}'.")
                self._write_user_plan()
                cmd = self._automation_command()
                env = os.environ.copy()
            elif self.auth_enabled:
                Logger.get_logger().debug("DAST scan: browser-based authentication enabled.")
                self._write_auth_plan(args, full_scan="zap-full-scan.py" in joined)
                cmd = self._automation_command()
                env = os.environ.copy()
            else:
                sanitized_args = self._build_dast_args(args, is_recognized_script)
                cmd, env = self._build_dast_command(sanitized_args)

            Logger.get_logger().debug(f"Running DAST scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)

            if result.stdout:
                Logger.get_logger().debug(result.stdout)
            if result.stderr:
                Logger.get_logger().error(result.stderr)

            if result.stdout:
                sanitized_stdout = result.stdout ##.replace("zap", "[scanner]")
                Logger.get_logger().debug(sanitized_stdout)
                if("-help" in self.command):
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

    def _build_dast_args(self, args, is_recognized_script):
        """
        Sanitize the raw command, remove conflicting report flags,
        and enforce JSON output.
        """
        if not self.container_mode and is_recognized_script:
            raise NotImplementedError(
                "DASTScanner currently supports zap.sh only"
            )

        # ZAP conflicting report flags
        forbidden_flags = []
        if is_recognized_script:
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

        if is_recognized_script:
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
            cmd = build_docker_run_prefix(workdir=self.container_workdir)
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

            if "site" not in zap_results:
                # Not the expected ZAP JSON report shape - fail closed rather than silently
                # reporting a clean scan.
                Logger.get_logger().error(
                    f"Unexpected DAST report format (no 'site' key) in {self.result_file}"
                )
                return 1

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
