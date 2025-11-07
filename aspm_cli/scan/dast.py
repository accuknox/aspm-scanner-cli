import subprocess
import json
import os
import shlex

from colorama import Fore
from aspm_cli.utils import config, docker_pull
from aspm_cli.utils.logger import Logger
from aspm_cli.tool.manager import ToolManager

class DASTScanner:
    zap_image = os.getenv("SCAN_IMAGE", "public.ecr.aws/k9v9d5v2/zaproxy/zap-stable:2.16.1")
    result_file = "results.json"

    def __init__(self, command="", severity_threshold=None, container_mode=True):
        """
        :param command: Raw CLI args string for zap scripts
                        Example: "zap-baseline.py -t https://example.com -J results.json -I"
        :param severity_threshold: Minimum severity to fail on ("High", "Medium", "Low", "Informational")
        :param container_mode: Currently only container mode is supported
        """
        self.command = command
        self.severity_threshold = severity_threshold
        self.container_mode = container_mode

    def run(self):
        try:
            if self.container_mode:
                docker_pull(self.zap_image)
                Logger.get_logger().debug("Starting DAST scan...")

            sanitized_args = self._build_dast_args()
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
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.getcwd()}:/zap/wrk",
                "-w", "/zap/wrk",
                "-t", self.zap_image
            ]
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
