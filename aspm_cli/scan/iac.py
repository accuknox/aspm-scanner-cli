import subprocess
import json
import os
from aspm_cli.utils import docker_pull

from aspm_cli.utils.logger import Logger

class IaCScanner:
    checkov_image = "ghcr.io/bridgecrewio/checkov:3.2.21"
    output_format = 'json'
    output_file_path = '.'
    result_file = f'{output_file_path}/results_json.json'

    def __init__(self, repo_url=None, repo_branch=None, file=None, directory=None, compact=False, quiet=False, framework=None):
        self.file = file
        self.directory = directory
        self.compact = compact
        self.quiet = quiet
        self.framework = framework
        self.repo_url = repo_url
        self.repo_branch = repo_branch

    def run(self):
        try:
            """Run the IaC scan using Checkov."""
            docker_pull(self.checkov_image)
            checkov_cmd = [
                "docker", "run", "--rm", "-v", f"{os.getcwd()}:/workdir", "--workdir", f"/workdir"
            ]
            checkov_cmd_init = list(checkov_cmd)
            checkov_cmd_init.extend(["--entrypoint", "bash"])

            checkov_cmd.append(self.checkov_image)
            checkov_cmd_init.append(self.checkov_image)

            if self.file:
                checkov_cmd.extend(["-f", self.file])
            if self.directory:
                checkov_cmd.extend(["-d", self.directory])
            if self.compact is True:
                checkov_cmd.append("--compact")
            if self.quiet is True:
                checkov_cmd.append("--quiet")
            checkov_cmd.extend(["-o", self.output_format, "--output-file-path", self.output_file_path])
            if self.framework:
                checkov_cmd.extend(["--framework", self.framework])

            Logger.get_logger().debug(f"Executing command: {' '.join(checkov_cmd)}")
            result = subprocess.run(checkov_cmd, capture_output=True, text=True)

            if(result.stdout):
                Logger.get_logger().debug(result.stdout)
            if(result.stderr):
                Logger.get_logger().error(result.stderr)

            checkov_cmd_init.extend(["-c", f"chmod 777 {self.result_file}"])
            subprocess.run(checkov_cmd_init, capture_output=True, text=True)

            if not os.path.exists(self.result_file):
                Logger.get_logger().info("No results found. Skipping API upload.")
                return result.returncode, None

            self.process_result_file()
            return result.returncode, self.result_file
        except Exception as e:
            Logger.get_logger().error(f"Error during IAC scan: {e}")
            raise

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
                    "branch":  self.repo_branch
                }
            })

            with open(self.result_file, 'w') as file:
                json.dump(data, file, indent=2)

            Logger.get_logger().debug("Result file processed successfully.")
        except Exception as e:
            Logger.get_logger().debug(f"Error processing result file: {e}")
            Logger.get_logger().error(f"Error during IAC scan: {e}")
            raise