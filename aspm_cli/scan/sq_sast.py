import subprocess
import os
import json
import re
import shlex
import sys
import asyncio
import requests
from urllib.parse import urlparse
from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import docker_pull
from aspm_cli.utils.docker_runtime import build_docker_run_prefix
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.subprocess_utils import utf8_text

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
        self.repo_url = self._valid_repo_url(self.repo_url)
        try:
            returncode = 0
            if not self.skip_sonar_scan:
                returncode = self._run_sq_scan()
                if returncode != 0:
                    # Nothing valid to fetch; surface the scanner error instead of a misleading fetch failure.
                    raise RuntimeError(f"SonarScanner failed with exit code {returncode}; see the error above.")
            else:
                Logger.get_logger().info("SQ SAST scan skipped.")
            result_file = self._run_ak_scan()
            self._process_result_file(result_file)
            if self._severity_threshold_met(result_file):
                Logger.get_logger().error(
                    f"Vulnerabilities matching severities: {', '.join(self.severity)} found."
                )
                return 1, result_file
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
                # macOS: the scanner's JVM fails reading the system keychain (posix_spawn of `security`).
                # shortcut: skips the OS truststore, so a server with a private CA needs sonar.scanner.truststore*.
                if sys.platform == "darwin" and not any("skipSystemTruststore" in a for a in cmd):
                    cmd.append("-Dsonar.scanner.skipSystemTruststore=true")

            Logger.get_logger().debug(f"Running scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, **utf8_text())

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
            try:
                from accuknox_sq_sast.sonarqube_fetcher import SonarQubeFetcher
            except ImportError as e:
                raise RuntimeError(
                    "accuknox-sq-sast is not installed. Reinstall with "
                    "`pip install accuknox-aspm-scanner` to pull it in."
                ) from e
            fetcher = SonarQubeFetcher(
                sq_url=self.sonar_host_url,
                auth_token=self.sonar_token,
                sq_projects=f"^{self.sonar_project_key}$",
                sq_org=self.sonar_org_id,
                report_path=""
            )
            results = asyncio.run(fetcher.fetch_all())
            # fetch_all() returns an error string (not a list) on failure.
            if not isinstance(results, list) or not results:
                raise RuntimeError(f"SonarQube fetch failed: {results or 'no result files produced'}")
            if len(results) == 1:
                return results[0]
            # One file per SonarQube branch: upload the --branch one (files are SQ-<key>-<branch>.json), else the first.
            chosen = next((r for r in results if r.endswith(f"-{self.branch}.json")), results[0])
            skipped = [r for r in results if r != chosen]
            Logger.get_logger().warning(
                f"Project has {len(results)} SonarQube branches; uploading {chosen}, skipping {skipped}. "
                "Run once per project key to cover the rest."
            )
            return chosen
        except Exception as e:
            Logger.get_logger().error(f"Error during AccuKnox SQ Fetcher: {e}")
            raise

    def _process_result_file(self, file_path):
        """Append metadata to result JSON."""
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)

            # CLI/git values win; otherwise take them from SonarQube (result branch, latest analysis revision).
            repo_details = {
                "repository_url": self.repo_url,
                "commit": self.commit_sha or self._analysis_revision(data.get("branch")),
                "branch": self.branch or data.get("branch"),
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

    def _valid_repo_url(self, url):
        """The backend parser needs a full URL with a host (e.g. https://github.com/org/repo.git)."""
        url = (url or "").strip()
        scp = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", url)  # git@github.com:org/repo.git
        if scp:
            url = f"https://{scp.group(1)}/{scp.group(2)}"
        if urlparse(url).hostname:
            return url
        fallback = f"https://localhost/{self.sonar_project_key or os.path.basename(os.getcwd())}"
        Logger.get_logger().warning(
            f"No repository URL from --repo-url or git; using '{fallback}'. "
            "Pass --repo-url so findings link to the real repository."
        )
        return fallback

    def _analysis_revision(self, branch):
        """Commit SHA of the project's latest SonarQube analysis, or None if unavailable."""
        try:
            params = {"project": self.sonar_project_key, "ps": 1}
            if branch:
                params["branch"] = branch
            r = requests.get(f"{self.sonar_host_url}/api/project_analyses/search", params=params,
                             auth=(self.sonar_token, ""), timeout=30)
            r.raise_for_status()
            analyses = r.json().get("analyses") or []
            return analyses[0].get("revision") if analyses else None
        except Exception as e:
            Logger.get_logger().debug(f"Could not read analysis revision from SonarQube: {e}")
            return None

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
