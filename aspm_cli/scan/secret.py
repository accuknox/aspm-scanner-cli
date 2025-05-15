import subprocess
import os
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger
import shlex

class SecretScanner:
    result_file = 'results.json'
    trufflehog_image = "trufflesecurity/trufflehog:3.88.29"

    def __init__(self, results=None, branch=None, exclude_paths=None, additional_arguments=None, base_command=None):
        self.results = results
        self.branch = branch
        self.exclude_paths = exclude_paths
        self.additional_arguments = additional_arguments
        self.base_command = base_command

    def run(self):
        try:
            if not self.base_command:
                docker_pull(self.trufflehog_image)
                Logger.get_logger().debug("Starting Secret Scan using TruffleHog...")

            cmd = self._build_trufflehog_command()
            Logger.get_logger().debug(f"Running command: {' '.join(cmd)}")

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout:
                Logger.get_logger().debug(result.stdout)
            if result.stderr:
                Logger.get_logger().error(result.stderr)

            with open(self.result_file, 'w') as f:
                f.write(result.stdout)

            Logger.get_logger().debug(f"Scan returncode: {result.returncode}")
            if os.path.exists(self.result_file) and os.stat(self.result_file).st_size > 0:
                return result.returncode, self.result_file
            else:
                Logger.get_logger().info("No secrets found. Skipping result file usage.")
                return result.returncode, None

        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during Secret scan: {e}")
            raise

    def _build_common_flags(self):
        """
        Helper function to build the common flags for trufflehog command
        """
        flags = [
            "--json",
            "--no-update",
            "--fail"
        ]

        if self.results:
            flags.extend(["--results", self.results])

        if self.exclude_paths:
            flags.extend(["-x", self.exclude_paths])

        if self.branch:
            branch_flag = f"--branch={self.branch}" if self.branch != "all-branches" else ""
            if branch_flag:
                flags.append(branch_flag)

        if self.additional_arguments:
            flags.extend(shlex.split(self.additional_arguments))

        return flags

    def _build_trufflehog_command(self):
        if self.base_command:
            cmd = self.base_command.split()
            is_docker = cmd[0] == "docker"
        else:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.getcwd()}:/app",
                self.trufflehog_image
            ]
            is_docker = True


        if is_docker:
            target_path = "file:///app"
        else:
            target_path = f"file://."

        cmd.extend(["git", target_path])
        cmd.extend(self._build_common_flags())
        return cmd