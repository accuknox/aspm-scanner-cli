import os
import shlex
import subprocess

from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import config, docker_pull
from aspm_cli.utils.logger import Logger
from colorama import Fore

TRUFFLEHOG_IMAGE = "public.ecr.aws/k9v9d5v2/trufflesecurity/trufflehog:3.90.3"
GITLEAKS_IMAGE = "ghcr.io/gitleaks/gitleaks:v8.24.2"


class SecretScanner:
    def __init__(self, command, container_mode=False, engine="trufflehog"):
        self.command = command
        self.container_mode = container_mode
        self.engine = engine.lower()

    @property
    def result_file(self):
        return "results.json" if self.engine == "gitleaks" else "results.jsonl"

    @property
    def scan_image(self):
        if self.engine == "gitleaks":
            return os.getenv("GITLEAKS_IMAGE", GITLEAKS_IMAGE)
        return os.getenv("SCAN_IMAGE", TRUFFLEHOG_IMAGE)

    def run(self):
        try:
            Logger.get_logger().debug(f"Starting secret scan using {self.engine}...")
            if self.container_mode:
                docker_pull(self.scan_image)

            if self.engine == "gitleaks":
                return self._run_gitleaks()
            return self._run_trufflehog()
        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during Secret scan: {e}")
            raise

    def _run_trufflehog(self):
        args = self._build_trufflehog_args()
        cmd = self._build_scan_command(args, tool_name="secret")
        return self._execute_scan(cmd, brand="TruffleHog", write_stdout=True)

    def _run_gitleaks(self):
        args = self._build_gitleaks_args()
        cmd = self._build_scan_command(args, tool_name="gitleaks", entrypoint_gitleaks=True)
        return self._execute_scan(cmd, brand="Gitleaks", write_stdout=False)

    def _execute_scan(self, cmd, brand: str, write_stdout: bool):
        Logger.get_logger().debug(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stdout:
            sanitized_stdout = result.stdout.replace(brand, "[scanner]")
            Logger.get_logger().debug(sanitized_stdout)
            if "--help" in (self.command or ""):
                Logger.log_with_color("INFO", sanitized_stdout, Fore.WHITE)
                return config.PASS_RETURN_CODE, None

        if result.stderr:
            sanitized_stderr = result.stderr.replace(brand, "[scanner]")
            if "--help" in (self.command or "") and result.returncode == 0:
                Logger.log_with_color("INFO", sanitized_stderr, Fore.WHITE)
                return config.PASS_RETURN_CODE, None
            Logger.get_logger().error(sanitized_stderr)

        if write_stdout:
            with open(self.result_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)

        if os.path.exists(self.result_file) and os.stat(self.result_file).st_size > 0:
            return result.returncode, self.result_file

        Logger.get_logger().info("No secrets found. Skipping upload.")
        return result.returncode, None

    def _build_trufflehog_args(self):
        args = shlex.split(self.command or "")
        forbidden_flags = {"--json", "--fail", "--no-update"}
        sanitized_args = [arg for arg in args if arg not in forbidden_flags]
        sanitized_args.extend(["--json", "--fail", "--no-update"])
        return sanitized_args

    def _build_gitleaks_args(self):
        if self.command and self.command.strip():
            return shlex.split(self.command)

        return [
            "detect",
            "--source", ".",
            "--report-format", "sarif",
            "--report-path", self.result_file,
            "--no-banner",
        ]

    def _build_scan_command(self, args, tool_name: str, entrypoint_gitleaks: bool = False):
        if not self.container_mode:
            return [ToolManager.get_path(tool_name), *args]

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.getcwd()}:/app",
            "--workdir", "/app",
        ]
        if entrypoint_gitleaks:
            cmd.extend(["--entrypoint", "gitleaks"])
        cmd.append(self.scan_image)
        cmd.extend(args)
        return cmd
