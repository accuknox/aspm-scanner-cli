import subprocess
import json
import os
import shlex
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger

class IaCScanner:
    checkov_image = "ghcr.io/bridgecrewio/checkov:3.2.21"
    output_format = 'json'
    output_file_path = '.'
    result_file = f'{output_file_path}/results_json.json'

    def __init__(self, repo_url=None, repo_branch=None, file=None, directory=None,
                 compact=False, quiet=False, framework=None, base_command=None):
        self.file = file
        self.directory = directory
        self.compact = compact
        self.quiet = quiet
        self.framework = framework
        self.repo_url = repo_url
        self.repo_branch = repo_branch
        self.base_command = base_command

    def run(self):
        try:
            if not self.base_command:
                docker_pull(self.checkov_image)

            checkov_cmd = self._build_checkov_command()

            Logger.get_logger().debug(f"Executing command: {' '.join(checkov_cmd)}")
            result = subprocess.run(checkov_cmd, capture_output=True, text=True)

            if result.stdout:
                Logger.get_logger().debug(result.stdout)
            if result.stderr:
                Logger.get_logger().error(result.stderr)

            self._fix_file_permissions_if_docker()

            if not os.path.exists(self.result_file):
                Logger.get_logger().info("No results found. Skipping API upload.")
                return result.returncode, None

            self.process_result_file()
            return result.returncode, self.result_file

        except Exception as e:
            Logger.get_logger().error(f"Error during IaC scan: {e}")
            raise

    def _build_checkov_command(self):
        if self.base_command:
            cmd = shlex.split(self.base_command)
            is_docker = cmd[0] == "docker"
        else:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.getcwd()}:/workdir",
                "--workdir", "/workdir",
                self.checkov_image
            ]
            print(cmd)
            is_docker = True

        if self.file:
            cmd.extend(["-f", self.file])
        if self.directory:
            cmd.extend(["-d", self.directory])
        if self.compact:
            cmd.append("--compact")
        if self.quiet:
            cmd.append("--quiet")
        if self.framework:
            cmd.extend(["--framework", self.framework])

        cmd.extend(["-o", self.output_format, "--output-file-path", self.output_file_path])

        return cmd

    def _fix_file_permissions_if_docker(self):
        # Only run chmod if using docker
        if not self.base_command or self.base_command.startswith("docker"):
            try:
                chmod_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{os.getcwd()}:/workdir",
                    "--workdir", "/workdir",
                    "--entrypoint", "bash",
                    self.checkov_image,
                    "-c", f"chmod 777 {self.result_file}"
                ]
                subprocess.run(chmod_cmd, capture_output=True, text=True)
            except Exception as e:
                Logger.get_logger().debug(f"Could not fix file permissions: {e}")

    def process_result_file(self):
        """Process the result JSON file to ensure it is an array and append additional metadata."""
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