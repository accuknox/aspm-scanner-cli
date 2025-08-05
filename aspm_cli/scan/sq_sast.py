import subprocess
import os
import json
import shlex
import asyncio
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger
from accuknox_sq_sast.sonarqube_fetcher import SonarQubeFetcher

class SQSASTScanner:
    sast_image = "sonarsource/sonar-scanner-cli:11.3"

    def __init__(self, skip_sonar_scan, command, non_container_mode=False, repo_url=None, branch=None,
                 commit_sha=None, pipeline_url=None):
        """
        :param command: Raw command string (e.g., "-Dsonar.projectKey=... -Dsonar.token=...")
        :param non_container_mode: If True, run sonar-scanner natively instead of Docker
        :param repo_url: Git repository URL
        :param branch: Branch name
        :param commit_sha: Git commit SHA
        :param pipeline_url: CI/CD pipeline URL
        """
        self.skip_sonar_scan = skip_sonar_scan
        self.command = command
        self.non_container_mode = non_container_mode
        self.repo_url = repo_url
        self.branch = branch
        self.commit_sha = commit_sha
        self.pipeline_url = pipeline_url

        # Extract needed values from command (for fetcher)
        self.sonar_project_key = self._extract_arg("-Dsonar.projectKey")
        self.sonar_token = self._extract_arg("-Dsonar.token")
        self.sonar_host_url = self._extract_arg("-Dsonar.host.url")
        self.sonar_org_id = self._extract_arg("-Dsonar.organization")

    def run(self):
        try:
            returncode = 0
            if not self.skip_sonar_scan:
                returncode = self._run_sq_scan()
            else:
                Logger.get_logger().info("SQ SAST scan skipped.")
            result_file = self._run_ak_scan()
            self._process_result_file(result_file)
            return returncode, result_file
        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"SonarQube-based AccuKnox SAST scan failed: {e}")
            raise

    def _run_sq_scan(self):
        try:
            Logger.get_logger().debug("Starting SonarQube-based AccuKnox SAST scan...")

            cmd = shlex.split(self.command)

            if not self.non_container_mode:
                docker_pull(self.sast_image)
                cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{os.getcwd()}:/usr/src/",
                    "--workdir", "/usr/src/",
                    self.sast_image
                ] + cmd
            else:
                cmd = ["sonar-scanner"] + cmd

            Logger.get_logger().debug(f"Running scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout:
                Logger.get_logger().debug(result.stdout)
            if result.stderr:
                Logger.get_logger().error(result.stderr)

            return result.returncode
        except Exception as e:
            Logger.get_logger().error(f"Error during SonarQube-based AccuKnox SAST scan: {e}")
            raise

    def _run_ak_scan(self):
        try:
            Logger.get_logger().debug("Starting AccuKnox SQ Fetcher...")
            fetcher = SonarQubeFetcher(
                sq_url=self.sonar_host_url,
                auth_token=self.sonar_token,
                sq_projects=f"^{self.sonar_project_key}$",
                sq_org=self.sonar_org_id,
                report_path=""
            )
            results = asyncio.run(fetcher.fetch_all())
            return results[0]
        except Exception as e:
            Logger.get_logger().error(f"Error during AccuKnox SQ Fetcher: {e}")
            raise

    def _process_result_file(self, file_path):
        """Append metadata to result JSON."""
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)

            repo_details = {
                "repository_url": self.repo_url,
                "commit": self.commit_sha,
                "branch": self.branch,
                "pipeline_url": self.pipeline_url
            }

            data["repo_details"] = repo_details

            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)

            Logger.get_logger().debug("Result file processed successfully.")
        except Exception as e:
            Logger.get_logger().debug(f"Error processing result file: {e}")
            Logger.get_logger().error(f"Error during SQ SAST scan: {e}")
            raise

    def _extract_arg(self, key):
        """Extracts a value from the raw command string (e.g. -Dsonar.projectKey=foo)."""
        for arg in shlex.split(self.command):
            if arg.startswith(key + "="):
                return arg.split("=", 1)[1]
        return None
