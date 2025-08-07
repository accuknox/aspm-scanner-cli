import subprocess
import os
import shlex
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger
from colorama import Fore
from aspm_cli.utils import config

class SecretScanner:
    ak_secretscan_image = os.getenv("SCAN_IMAGE", "trufflesecurity/trufflehog:3.90.3")
    result_file = 'results.json'

    def __init__(self, command, container_mode=False):
        """
        :param command: Raw ak_secretscan CLI arguments string
        :param container_mode: Run locally if True, else use Docker
        """
        self.command = command
        self.container_mode = container_mode

    def run(self):
        try:
            Logger.get_logger().debug("Starting Secret Scan using ak_secretscan...")
            if self.container_mode:
                docker_pull(self.ak_secretscan_image)

            args = self._build_secretscan_args()
            cmd = self._build_secretscan_command(args)

            Logger.get_logger().debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout:
                sanitized_stdout = result.stdout.replace("TruffleHog", "[scanner]")
                Logger.get_logger().debug(sanitized_stdout)

                if("--help" in self.command):
                    Logger.log_with_color('INFO', sanitized_stdout, Fore.WHITE)
                    return config.PASS_RETURN_CODE, None
            if result.stderr:
                sanitized_stderr = result.stderr.replace("TruffleHog", "[scanner]")

                if("--help" in self.command and result.returncode == 0):
                    Logger.log_with_color('INFO', sanitized_stderr, Fore.WHITE)
                    return config.PASS_RETURN_CODE, None
                else:
                    Logger.get_logger().error(sanitized_stderr)

            with open(self.result_file, 'w') as f:
                f.write(result.stdout)

            if os.path.exists(self.result_file) and os.stat(self.result_file).st_size > 0:
                return result.returncode, self.result_file
            else:
                Logger.get_logger().info("No secrets found. Skipping upload.")
                return result.returncode, None

        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during Secret scan: {e}")
            raise

    def _build_secretscan_args(self):
        """
        Parse raw command, filter conflicting flags, and append mandatory ones.
        """
        args = shlex.split(self.command)

        # Strip known conflicting or redundant flags
        forbidden_flags = {"--json", "--fail", "--no-update"}
        sanitized_args = []
        i = 0
        while i < len(args):
            if args[i] in forbidden_flags:
                i += 1
                continue
            sanitized_args.append(args[i])
            i += 1

        sanitized_args.extend(["--json", "--fail", "--no-update"])
        return sanitized_args

    def _build_secretscan_command(self, args):
        """
        Construct the full command with target and args.
        """
        if not self.container_mode:
            cmd = ["trufflehog"]
        else:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.getcwd()}:/app",
                "--workdir", "/app",
                self.ak_secretscan_image
            ]

        cmd.extend(args)
        return cmd