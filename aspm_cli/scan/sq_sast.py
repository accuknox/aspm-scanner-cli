import subprocess
import os
import json
import re
import shlex
import sys
import time
import asyncio
import base64
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlparse
from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import docker_pull
from aspm_cli.utils.docker_runtime import build_docker_run_prefix
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.subprocess_utils import utf8_text
from aspm_cli.utils.tls import download_context

class SQSASTScanner:
    sast_image = os.getenv("SCAN_IMAGE", "public.ecr.aws/k9v9d5v2/sonarsource/sonar-scanner-cli:11.4")
    _poll_seconds = 3  # between checks of the SonarQube background task
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
        # The fetcher strips a trailing slash; do the same so our own API calls don't hit "//api/...".
        self.sonar_host_url = (self._extract_arg("-Dsonar.host.url") or "").rstrip("/") or None
        self.sonar_org_id = self._extract_arg("-Dsonar.organization")
        self.sonar_branch = self._extract_arg("-Dsonar.branch.name")
        self._analysis_ok = False
        # ceTaskId in report-task.txt before this scan ran (a leftover from an earlier run).
        self._prev_task_id = None
        # Task id the scanner printed for this run ("More about the report processing at .../api/ce/task?id=").
        self._stdout_task_id = None
        # Set by _run_ak_scan when SonarQube returns several branches: the branch of the file uploaded,
        # and whether the git commit describes that data.
        self._chosen_branch = None
        self._use_git_commit = True
        # Branch the SonarQube background task reports for this run's analysis (None on the main branch).
        self._task_branch = None

    def run(self):
        self.repo_url = self._valid_repo_url(self.repo_url)
        try:
            returncode = 0
            if not self.skip_sonar_scan:
                self._prev_task_id = self._task_id()
                returncode = self._run_sq_scan()
                # A non-zero exit after a completed analysis is a quality-gate failure: still upload.
                if returncode != 0 and not (self._analysis_ok or self._fresh_task_file()):
                    # The analysis never completed: don't fetch (that would upload the previous analysis).
                    # Return the code instead of raising so the caller still applies --softfail and warns
                    # a waiting quality gate that no result is coming.
                    Logger.get_logger().error(
                        f"SonarScanner failed with exit code {returncode}; not fetching results. "
                        "Run with debug logging to see the scanner output."
                    )
                    return returncode, None
            else:
                Logger.get_logger().info("SQ SAST scan skipped.")
            if not self.skip_sonar_scan and not self._wait_for_analysis():
                # Fetching now would upload the previous analysis. Return a code (not raise) so --softfail applies.
                return returncode or 1, None
            result_file = self._run_ak_scan()
            self._process_result_file(result_file)
            if self._severity_threshold_met(result_file):
                Logger.get_logger().error(
                    f"Vulnerabilities matching severities: {', '.join(self.severity)} found."
                )
                return 1, result_file
            return returncode, result_file
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
            result = subprocess.run(cmd, capture_output=True, **utf8_text())
            # macOS: the scanner's JVM can fail reading the keychain (posix_spawn of `security`). Retry without
            # the OS truststore; defaulting to it would break corporate CAs installed in the keychain.
            if (result.returncode != 0 and sys.platform == "darwin" and not self.container_mode
                    and "MacCertificateUtils" in (result.stdout or "") + (result.stderr or "")
                    and not any("skipSystemTruststore" in a for a in cmd)):
                Logger.get_logger().warning("Scanner could not read the macOS keychain; retrying without the system truststore.")
                cmd = cmd + ["-Dsonar.scanner.skipSystemTruststore=true"]
                result = subprocess.run(cmd, capture_output=True, **utf8_text())
            self._analysis_ok = "ANALYSIS SUCCESSFUL" in (result.stdout or "")
            task = re.search(r"/api/ce/task\?id=([\w-]+)", result.stdout or "")
            self._stdout_task_id = task.group(1) if task else None

            if result.stdout:
                Logger.get_logger().debug(result.stdout)
                if result.returncode != 0:
                    # The scanner writes its errors to stdout; show them without needing debug logging.
                    for line in result.stdout.splitlines():
                        if "ERROR" in line:
                            Logger.get_logger().error(line)
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
                sq_projects=f"^{re.escape(self.sonar_project_key or '')}$",
                sq_org=self.sonar_org_id,
                report_path=""
            )
            results = asyncio.run(fetcher.fetch_all())
            # fetch_all() returns an error string (not a list) on failure.
            if not isinstance(results, list) or not results:
                raise RuntimeError(f"SonarQube fetch failed: {results or 'no result files produced'}")
            if len(results) == 1:
                return results[0]
            chosen = None
            try:
                chosen = self._choose_branch_file(results)
                return chosen
            finally:
                # The other branches' files hold full issue data and code snippets: don't leave them
                # in the checkout where a later `git add` could pick them up.
                for path in results:
                    if path != chosen:
                        try:
                            os.remove(path)
                        except OSError:
                            pass
        except Exception as e:
            Logger.get_logger().error(f"Error during AccuKnox SQ Fetcher: {e}")
            raise

    def _choose_branch_file(self, results):
        """Pick one of the per-branch result files and record which branch it holds."""
        # One file per SonarQube branch. Match on the exact branch stored inside each file, since
        # file names replace "/" with "_".
        by_branch = {self._file_branch(r): r for r in results}
        ran = not self.skip_sonar_scan
        # After a scan, the branch is the one SonarQube analysed: -Dsonar.branch.name, else what its
        # background task reports, else its main branch. The git branch is only used to pick existing
        # results (--skip-sonar-scan); a same-named SonarQube branch may hold an older analysis.
        wanted = self.sonar_branch or (self._task_branch if ran else self.branch)
        hint = "-Dsonar.branch.name" if self.sonar_branch or ran else "--branch"
        if wanted in by_branch:
            self._chosen_branch = wanted
            # This run analysed the local checkout into `wanted`, so its commit describes the data.
            # Without a scan, that only holds when the checkout is on that same branch.
            self._use_git_commit = ran or wanted == self.branch
            Logger.get_logger().warning(
                f"Project has {len(results)} SonarQube branches; uploading '{wanted}' only. "
                f"Re-run with {hint} set to each of the others to cover them."
            )
            return by_branch[wanted]
        main = self._main_branch()
        if main not in by_branch:
            raise RuntimeError(
                f"Project has {len(results)} SonarQube branches ({', '.join(str(b) for b in by_branch)}) "
                f"and none is '{wanted}'. Set {hint} to one of them."
            )
        self._chosen_branch = main
        if wanted is None:
            # A scan without a branch name lands on SonarQube's main branch, so the local commit
            # describes it. Without a scan (detached HEAD) the commit is unrelated.
            self._use_git_commit = ran
            Logger.get_logger().warning(
                f"Project has {len(results)} SonarQube branches; uploading its main branch '{main}'. "
                f"Set {hint} to choose another."
            )
        else:
            # A different branch's data: the git commit doesn't describe it.
            self._use_git_commit = False
            Logger.get_logger().warning(
                f"SonarQube has no branch '{wanted}'; uploading its main branch '{main}' instead."
            )
        return by_branch[main]

    @staticmethod
    def _file_branch(path):
        with open(path, "r") as f:
            return json.load(f).get("branch")

    def _sq_get(self, url, params=None):
        """GET a SonarQube API URL and return its JSON.

        Uses the system CA store plus certifi, like the aiohttp fetcher, so a SonarQube signed by a
        corporate CA works here too (requests would trust certifi only).
        """
        if params:
            url = f"{url}?{urlencode(params)}"
        token = base64.b64encode(f"{self.sonar_token or ''}:".encode()).decode()
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
        with urllib.request.urlopen(req, timeout=30, context=download_context()) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _main_branch(self):
        """Name of the SonarQube project's main branch, or None if unavailable."""
        try:
            data = self._sq_get(f"{self.sonar_host_url}/api/project_branches/list",
                                {"project": self.sonar_project_key})
            return next((b.get("name") for b in data.get("branches", []) if b.get("isMain")), None)
        except Exception as e:
            Logger.get_logger().warning(f"Could not read the SonarQube main branch: {e}")
            return None

    def _task_file(self):
        # shortcut: container mode with a container-side projectBaseDir is not translated, use the cwd.
        base = self._extract_arg("-Dsonar.projectBaseDir") or os.getcwd()
        work = self._extract_arg("-Dsonar.working.directory") or ".scannerwork"
        return os.path.join(base, work, "report-task.txt")

    def _task_id(self):
        """ceTaskId from report-task.txt, or None when there is no such file."""
        try:
            with open(self._task_file()) as f:
                return dict(l.strip().split("=", 1) for l in f if "=" in l).get("ceTaskId")
        except OSError:
            return None

    def _new_task_id(self):
        """Id of the SonarQube background task this scan submitted, or None if it submitted none."""
        # The scanner prints it; the container image keeps report-task.txt inside the container, so
        # the file is only a fallback (quiet scanner logging). Every analysis gets a new id, so the
        # same id as before the scan is a leftover from an earlier run (self-hosted runner). Not the
        # file's timestamp: clocks differ between host, container and network drives.
        if self._stdout_task_id:
            return self._stdout_task_id
        task_id = self._task_id()
        return task_id if task_id != self._prev_task_id else None

    def _fresh_task_file(self):
        """True if this scan submitted an analysis to SonarQube."""
        return bool(self._new_task_id())

    def _wait_for_analysis(self, timeout=300):
        """SonarQube processes the scan in the background; wait for it so the fetch sees this analysis.

        Returns False when that processing failed or did not finish, i.e. there is nothing new to fetch.
        """
        task_id = self._new_task_id()
        if not task_id:
            Logger.get_logger().warning(
                f"No background task id in the scanner output or in {self._task_file()}; cannot wait for "
                "SonarQube to finish processing, so results may be from the previous analysis."
            )
            return True
        # Not the file's ceTaskUrl: that is built from the server's configured base URL, which can be
        # another host or plain http, and the token must only go to -Dsonar.host.url.
        url = f"{self.sonar_host_url}/api/ce/task"
        deadline = time.time() + timeout
        error = None
        while time.time() < deadline:
            try:
                task = self._sq_get(url, {"id": task_id}).get("task", {})
            except urllib.error.HTTPError as e:
                if e.code in (401, 403, 404):
                    # The token cannot read the task; retrying will not help.
                    Logger.get_logger().warning(
                        f"Could not check the SonarQube background task (HTTP {e.code}); results may be stale."
                    )
                    return True
                error = e
            except Exception as e:
                error = e  # a timeout or 5xx while the server is busy: keep polling
            else:
                status = task.get("status")
                if status in ("FAILED", "CANCELED"):
                    Logger.get_logger().error(
                        f"SonarQube background task {status}: {task.get('errorMessage') or 'no reason given'}. "
                        "Not fetching results."
                    )
                    return False
                if status == "SUCCESS":
                    self._task_branch = task.get("branch")
                    return True
            time.sleep(self._poll_seconds)
        Logger.get_logger().error(
            f"SonarQube did not finish processing the analysis within {timeout}s"
            f"{f' (last error: {error})' if error else ''}; not fetching results. "
            "Re-run with --skip-sonar-scan once it has finished."
        )
        return False

    def _process_result_file(self, file_path):
        """Append metadata to result JSON."""
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)

            file_branch = data.get("branch")
            if self._chosen_branch is None:
                # Single result: CLI/git values win; otherwise take them from SonarQube.
                branch = self.branch or file_branch
            else:
                # Several branches: label the data with the branch it actually came from.
                branch = self._chosen_branch
            commit = (self.commit_sha if self._use_git_commit else None) or self._analysis_revision(file_branch)
            repo_details = {
                "repository_url": self.repo_url,
                "commit": commit,
                "branch": branch,
                "pipeline_url": self.pipeline_url
            }
            self._align_upload_identity(branch, commit)

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
        if "://" not in url:
            # git@gitlab:team/app.git (user@ makes any host name unambiguous), gitlab:2222/team/app
            m = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", url) or re.match(r"^([\w.-]+:\d+)/(.+)$", url)
            if m:
                url = f"https://{m.group(1)}/{m.group(2)}"
        if "://" not in url:
            # github.com:org/repo.git, github.com/org/repo
            m = re.match(r"^(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+)(?::(?!\d+(?:/|$))|/)(.+)$", url)
            if m:
                url = f"https://{m.group(1)}/{m.group(2)}"
        if urlparse(url).hostname:
            return url
        fallback = f"https://localhost/{self.sonar_project_key or os.path.basename(os.getcwd())}"
        Logger.get_logger().warning(
            f"No repository URL from --repo-url or git; using '{fallback}'. "
            "Pass --repo-url so findings link to the real repository."
        )
        return fallback

    def _align_upload_identity(self, branch, commit):
        """Make the upload's branch/commit query parameters match repo_details.

        collect_ingest_identity() builds them from CI variables or git (it never sees --branch), which
        differ from the data when another SonarQube branch was uploaded. Its ACCUKNOX_BRANCH /
        ACCUKNOX_COMMIT_SHA overrides are used for this; values the user set themselves are left alone.
        """
        if self._chosen_branch is None:
            return
        if branch and not os.getenv("ACCUKNOX_BRANCH"):
            os.environ["ACCUKNOX_BRANCH"] = branch
        if commit and not os.getenv("ACCUKNOX_COMMIT_SHA"):
            os.environ["ACCUKNOX_COMMIT_SHA"] = commit

    def _analysis_revision(self, branch):
        """Commit SHA of the project's latest SonarQube analysis, or None if unavailable."""
        try:
            params = {"project": self.sonar_project_key, "ps": 1}
            if branch:
                params["branch"] = branch
            data = self._sq_get(f"{self.sonar_host_url}/api/project_analyses/search", params)
            analyses = data.get("analyses") or []
            return analyses[0].get("revision") if analyses else None
        except Exception as e:
            Logger.get_logger().warning(f"Could not read the analysis revision from SonarQube: {e}")
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
