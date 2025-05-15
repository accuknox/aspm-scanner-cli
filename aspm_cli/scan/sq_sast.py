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

    def __init__(self, skip_sonar_scan=True, sonar_project_key=None, sonar_token=None, sonar_host_url=None,
                 sonar_org_id=None, repo_url=None, branch=None, commit_sha=None, pipeline_url=None,
                 base_command=None):
        self.skip_sonar_scan = skip_sonar_scan
        self.sonar_project_key = sonar_project_key
        self.sonar_token = sonar_token
        self.sonar_host_url = sonar_host_url
        self.sonar_org_id = sonar_org_id

        self.repo_url = repo_url
        self.commit_sha = commit_sha
        self.branch = branch
        self.pipeline_url = pipeline_url

        self.base_command = base_command

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
            Logger.get_logger().error(f"SAST scan failed: {e}")
            raise

    def _run_sq_scan(self):
        try:
            if not self.base_command:
                docker_pull(self.sast_image)

            Logger.get_logger().debug("Starting SonarQube-based AccuKnox SAST scan...")
            if self.base_command:
                cmd = shlex.split(self.base_command)
            else:
                cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{os.getcwd()}:/usr/src/",
                    self.sast_image
                ]

            org_option = f"-Dsonar.organization={self.sonar_org_id}" if self.sonar_org_id else ""
            cmd.extend([
                f"-Dsonar.projectKey={self.sonar_project_key}",
                f"-Dsonar.host.url={self.sonar_host_url}",
                f"-Dsonar.token={self.sonar_token}",
                f"-Dsonar.qualitygate.wait=true"
            ])
            if org_option:
                cmd.append(org_option)

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