import os
import subprocess

from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import config, docker_pull
from aspm_cli.utils.docker_runtime import build_docker_run_prefix
from aspm_cli.utils.api_discovery import (
    DEFAULT_RESULT_FILE,
    DOCKER_WORKDIR,
    normalize_code2api_args,
    normalize_code2api_args_for_docker,
)
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.path_safety import resolve_path_within_root
from aspm_cli.utils.subprocess_utils import run_scan_subprocess
from colorama import Fore

CODE2API_IMAGE = os.getenv(
    "CODE2API_IMAGE",
    "public.ecr.aws/k9v9d5v2/accuknox/code2api:0.1.0",
)


class APIDiscoveryScanner:
    result_file = DEFAULT_RESULT_FILE

    def __init__(self, command, container_mode=False):
        self.command = command
        self.container_mode = container_mode
        self.scan_image = os.getenv("SCAN_IMAGE", CODE2API_IMAGE)
        self.cwd = os.getcwd()

    def run(self):
        try:
            if self.container_mode:
                docker_pull(self.scan_image)

            args = normalize_code2api_args(self.command, self.result_file)
            if "-version" in args:
                cmd = self._build_scan_command(["-version"])
                result = run_scan_subprocess(cmd)
                if result.stdout:
                    Logger.log_with_color("INFO", result.stdout, Fore.WHITE)
                return config.PASS_RETURN_CODE, None

            try:
                path_idx = args.index("-path")
                if path_idx + 1 < len(args):
                    resolve_path_within_root(args[path_idx + 1], self.cwd)
            except ValueError as exc:
                Logger.get_logger().error(str(exc))
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

            if self.container_mode:
                args = normalize_code2api_args_for_docker(args, cwd=self.cwd)

            cmd = self._build_scan_command(args)

            Logger.get_logger().debug(f"Running API discovery scan: {' '.join(cmd)}")
            result = run_scan_subprocess(cmd)

            if result.stdout:
                Logger.get_logger().debug(
                    result.stdout.replace("code2api", "[scanner]")
                )
            if result.stderr:
                Logger.get_logger().error(
                    result.stderr.replace("code2api", "[scanner]")
                )

            if os.path.exists(self.result_file) and os.stat(self.result_file).st_size > 0:
                return result.returncode, self.result_file

            if result.returncode == 0:
                Logger.get_logger().info(
                    "API discovery completed with no output file (no APIs found or empty scan)."
                )
            return result.returncode, None
        except subprocess.TimeoutExpired:
            Logger.get_logger().error("API discovery scan timed out")
            return config.SOMETHING_WENT_WRONG_RETURN_CODE, None
        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during API discovery scan: {e}")
            raise

    def _resolve_local_binary(self) -> str:
        try:
            return ToolManager.get_path("api-discovery")
        except (ValueError, FileNotFoundError):
            return "code2api"

    def _build_scan_command(self, args):
        if not self.container_mode:
            return [self._resolve_local_binary(), *args]

        return [
            *build_docker_run_prefix(workdir=DOCKER_WORKDIR, host_path=self.cwd),
            self.scan_image,
            *args,
        ]


