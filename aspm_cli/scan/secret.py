import subprocess
import os
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger

class SecretScanner:
    result_file = 'results.json'
    trufflehog_image = "trufflesecurity/trufflehog:3.88.29"

    def __init__(self, results=None, branch=None, exclude_paths=None, additional_arguments=None):
        self.results = results
        self.branch = branch
        self.exclude_paths = exclude_paths
        self.additional_arguments = additional_arguments

    def run(self):
        try:
            docker_pull(self.trufflehog_image)
            Logger.get_logger().debug("Starting Secret Scan using TruffleHog...")
            cmd = self._build_trufflehog_command()
            Logger.get_logger().debug(f"Running command: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True)

            if(result.stdout):
                Logger.get_logger().debug(result.stdout)
            if(result.stderr):
                Logger.get_logger().error(result.stderr)

            with open(self.result_file, 'w') as f:
                f.write(result.stdout)

            if os.path.exists(self.result_file) and os.stat(self.result_file).st_size > 0:
                return result.returncode, self.result_file
            else:
                Logger.get_logger().info("No secrets found. Skipping result file usage.")
                return result.returncode, None

        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during Secret scan: {e}")
            raise

    def _build_trufflehog_command(self):
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.getcwd()}:/app",
            self.trufflehog_image,
            "git", f"file:///app", 
            "--json",
            "--no-update",
            "--fail",
        ]

        if self.results:
            cmd.extend(["--results", self.results])

        if self.exclude_paths:
            cmd.extend(["-x", self.exclude_paths])

        branch_flag = ""
        if self.branch == "all-branches":
            branch_flag = ""
        elif self.branch:
            branch_flag = f"--branch={self.branch}"

        if branch_flag:
            cmd.append(branch_flag)

        if self.additional_arguments:
            cmd.extend(self.additional_arguments.split())

        return cmd
