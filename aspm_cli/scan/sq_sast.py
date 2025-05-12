import subprocess
import os
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger
import json
from accuknox_sq_sast.sonarqube_fetcher import SonarQubeFetcher
import asyncio

class SQSASTScanner:
    sast_image = "sonarsource/sonar-scanner-cli:11.3"

    def __init__(self, skip_sonar_scan= True, sonar_project_key = None, sonar_token = None, sonar_host_url = None, sonar_org_id=None,
                 repo_url=None, branch=None, commit_sha=None, pipeline_url= None):
        
        self.skip_sonar_scan = skip_sonar_scan
        self.sonar_project_key = sonar_project_key
        self.sonar_token = sonar_token
        self.sonar_host_url = sonar_host_url
        self.sonar_org_id = sonar_org_id

        self.repo_url = repo_url
        self.commit_sha = commit_sha
        self.branch = branch
        self.pipeline_url = pipeline_url

    def run(self):
        try:
            returncode = 0
            if(self.skip_sonar_scan is not True):
                returncode = self._run_sq_scan()
            else:
                Logger.get_logger().info(f"SQ SAST scan skipped")
            result_file = self._run_ak_scan()
            self._process_result_file(result_file)
            return returncode, result_file
        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"SAST scan failed: {e}")
            raise

    def _run_sq_scan(self):
        try:
            docker_pull(self.sast_image)
            Logger.get_logger().debug("Starting SonarQube-based AccuKnox SAST scan...")

            org_option = f"-Dsonar.organization={self.sonar_org_id}" if self.sonar_org_id and self.sonar_org_id.strip() else ""

            cmd = [
                "docker", "run", "--rm",
                "-e", f"SONAR_HOST_URL={self.sonar_host_url}",
                "-e", f"SONAR_TOKEN={self.sonar_token}",
                "-e", f"SONAR_SCANNER_OPTS=-Dsonar.projectKey={self.sonar_project_key} {org_option} -Dsonar.qualitygate.wait=true",
                "-v", f"{os.getcwd()}:/usr/src/",
                self.sast_image
            ]

            Logger.get_logger().debug(f"Running scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            Logger.get_logger().debug(result.stdout)
            Logger.get_logger().error(result.stderr)
            return result.returncode
        except Exception as e:
            Logger.get_logger().error(f"Error during SonarQube-based AccuKnox SAST scan...: {e}")
            raise

    def _run_ak_scan(self):
        try:
            Logger.get_logger().debug("Starting AccuKnox SQ Fetcher...")
            fetcher = SonarQubeFetcher(
                sq_url=self.sonar_host_url,
                auth_token=self.sonar_token,
                sq_projects=self.sonar_project_key,
                sq_org=self.sonar_org_id,
                report_path=""
            )
            results = asyncio.run(fetcher.fetch_all())
            return results[0]
        except Exception as e:
            Logger.get_logger().error(f"Error during AccuKnox SQ Fetcher...: {e}")
            raise

    def _process_result_file(self, file_path):
        """Process the result JSON file to ensure it is an array and append additional metadata."""
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
            Logger.get_logger().error(f"Error during IAC scan: {e}")
            raise