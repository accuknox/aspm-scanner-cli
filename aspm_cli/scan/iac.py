import subprocess
import json
import os
import shlex
from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger
from colorama import Fore
from aspm_cli.utils import config

class IaCScanner:
    ak_iac_image = os.getenv("SCAN_IMAGE", "bridgecrew/checkov:3.2.458")
    output_format = 'json'
    output_file_path = '.'
    result_file = os.path.join(output_file_path, 'results_json.json')

    def __init__(self, command, container_mode=False, repo_url=None, repo_branch=None):
        """
        :param command: Raw command string passed by the user (e.g., "-d .")
        :param container_mode: If True, run ak_iac locally instead of in Docker
        """
        self.command = command
        self.container_mode = container_mode
        self.repo_url = repo_url
        self.repo_branch = repo_branch

    def run(self):
        try:
            if self.container_mode:
                docker_pull(self.ak_iac_image)

            sanitized_args = self._build_iac_args()
            iac_cmd = self._build_iac_command(sanitized_args)

            Logger.get_logger().debug(f"Executing command: {' '.join(iac_cmd)}")
            result = subprocess.run(iac_cmd, capture_output=True, text=True)

            if result.stdout:
                sanitized_stdout = result.stdout.replace("checkov", "[scanner]")
                Logger.get_logger().debug(sanitized_stdout)
                if("--help" in self.command):
                    Logger.log_with_color('INFO', sanitized_stdout, Fore.WHITE)
                    return config.PASS_RETURN_CODE, None
            if result.stderr:
                sanitized_stderr = result.stderr.replace("checkov", "[scanner]")
                Logger.get_logger().error(sanitized_stderr)

            self._fix_file_permissions_if_docker()

            if not os.path.exists(self.result_file):
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

            self.process_result_file()
            return result.returncode, self.result_file

        except Exception as e:
            Logger.get_logger().error(f"Error during IaC scan: {e}")
            raise

    def _build_iac_args(self):
        """
        Sanitize the raw command and enforce output flags.
        """
        args = shlex.split(self.command)
        # Remove conflicting output flags if present
        forbidden_flags = {"-o", "--output-file-path"}
        sanitized_args = []
        i = 0
        while i < len(args):
            if args[i] in forbidden_flags:
                i += 2  # Skip flag and value
                continue
            sanitized_args.append(args[i])
            i += 1

        sanitized_args.extend([
            "-o", self.output_format,
            "--output-file-path", self.output_file_path,
            "--quiet"
        ])

        return sanitized_args

    def _build_iac_command(self, args):
        if not self.container_mode:
            return [ToolManager.get_path("iac")] + args

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.getcwd()}:/workdir",
            "--workdir", "/workdir",
            self.ak_iac_image
        ]
        cmd.extend(args)
        return cmd

    def _fix_file_permissions_if_docker(self):
        if self.container_mode:
            try:
                chmod_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{os.getcwd()}:/workdir",
                    "--workdir", "/workdir",
                    "--entrypoint", "bash",
                    self.ak_iac_image,
                    "-c", f"chmod 777 {self.result_file}"
                ]
                subprocess.run(chmod_cmd, capture_output=True, text=True)
            except Exception as e:
                Logger.get_logger().debug(f"Could not fix file permissions: {e}")

    def process_result_file(self):
        try:
            with open(self.result_file, 'r') as file:
                data = json.load(file)

            if isinstance(data, dict):
                data = [data]

            data.append({
                "details": {
                    "repo":   self.repo_url,
                    "branch": self.repo_branch
                }
            })

            with open(self.result_file, 'w') as file:
                json.dump(data, file, indent=2)

            Logger.get_logger().debug("Result file processed successfully.")
        except Exception as e:
            Logger.get_logger().debug(f"Error processing result file: {e}")
            Logger.get_logger().error(f"Error during IaC scan: {e}")
            raise