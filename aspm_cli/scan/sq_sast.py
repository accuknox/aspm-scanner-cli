import subprocess
import os
import json
import shlex
import asyncio
from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import docker_pull
from aspm_cli.utils.docker_runtime import build_docker_run_prefix
from aspm_cli.utils.logger import Logger
from accuknox_sq_sast.sonarqube_fetcher import SonarQubeFetcher

class SQSASTScanner:
    sast_image = os.getenv("SCAN_IMAGE", "public.ecr.aws/k9v9d5v2/sonarsource/sonar-scanner-cli:11.4")
    DEFAULT_SEVERITY = "INFO,MINOR,MAJOR,CRITICAL,BLOCKER,LOW,MEDIUM,HIGH"

    def __init__(self, skip_sonar_scan, command, container_mode=False, repo_url=None, branch=None,
                 commit_sha=None, pipeline_url=None, severity=None):
        """
        :param command: Raw command string (e.g., "-Dsonar.projectKey=... -Dsonar.token=...")
        :param container_mode: If True, run sonar-scanner natively instead of Docker
        :param repo_url: Git repository URL
        :param branch: Branch name
        :param commit_sha: Git commit SHA
        :param pipeline_url: CI/CD pipeline URL
        :param severity: Comma-separated severities that fail the scan
        """
        self.skip_sonar_scan = skip_sonar_scan
        self.command = command
        self.container_mode = container_mode
        self.repo_url = repo_url
        self.branch = branch
        self.commit_sha = commit_sha
        self.pipeline_url = pipeline_url
        self.severity = [
            s.strip().upper()
            for s in (severity or self.DEFAULT_SEVERITY).split(",")
            if s.strip()
        ]

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
            if self._severity_threshold_met(result_file):
                Logger.get_logger().error(
                    f"Vulnerabilities matching severities: {', '.join(self.severity)} found."
                )
                return 1, result_file
            # Prefer severity gating for findings; still surface scanner hard failures.
            if returncode != 0:
                return returncode, result_file
            return 0, result_file
        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"SonarQube-based AccuKnox SAST scan failed: {e}")
            raise

    def _run_sq_scan(self):
        try:
            Logger.get_logger().debug("Starting SonarQube-based AccuKnox SAST scan...")

            cmd = shlex.split(self.command)

            if self.container_mode:
                docker_pull(self.sast_image)
                cmd = build_docker_run_prefix(workdir="/usr/src", host_path=os.getcwd())
                cmd.append(self.sast_image)
                cmd.extend(shlex.split(self.command))
            else:
                cmd = [ToolManager.get_path("sq-sast")] + cmd

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

    def _severity_threshold_met(self, file_path):
        """
        Return True if any SonarQube issue severity or hotspot vulnerability
        probability matches the configured --severity list.
        """
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            for issue in data.get("issues") or []:
                severity = (issue.get("severity") or "").upper()
                if severity in self.severity:
                    return True

            for hotspot in data.get("hotspots") or []:
                probability = (hotspot.get("vulnerabilityProbability") or "").upper()
                if probability in self.severity:
                    return True

            return False
        except Exception as e:
            Logger.get_logger().error(f"Error evaluating SQ SAST severity threshold: {e}")
            raise

    def _extract_arg(self, key):
        """Extracts a value from the raw command string (e.g. -Dsonar.projectKey=foo)."""
        for arg in shlex.split(self.command):
            if arg.startswith(key + "="):
                return arg.split("=", 1)[1]
        return None
