import subprocess
import json
import os
import shlex
from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger
from colorama import Fore
from aspm_cli.utils import config
from urllib.parse import urlparse
import re

class SASTScanner:
    opengrep_image = os.getenv("SCAN_IMAGE", "public.ecr.aws/k9v9d5v2/accuknox/opengrepjob:0.1.0")
    result_file = "results.json"

    def __init__(self, command=None, container_mode=True, severity = None,
                 repo_url=None, commit_ref=None, commit_sha=None,
                 pipeline_id=None, job_url=None):
        """
        :param command: Raw OpenGrep CLI args (string)
        :param container_mode: Run in Docker if True, else use local binary
        :param repo_url: Git repository URL
        :param commit_ref: Branch or ref
        :param commit_sha: Commit SHA
        :param pipeline_id: CI pipeline ID
        :param job_url: CI job URL
        """
        self.command = command
        self.container_mode = container_mode
        self.severity = [s.strip().upper() for s in (severity).split(',')]
        self.repo_url = repo_url
        self.commit_ref = commit_ref
        self.commit_sha = commit_sha
        self.pipeline_id = pipeline_id
        self.job_url = job_url

    def run(self):
        try:
            Logger.get_logger().debug("Starting SAST scan...")

            if self.container_mode:
                docker_pull(self.opengrep_image)

            args = self._build_sast_args()
            cmd = self._build_sast_command(args)

            Logger.get_logger().debug(f"Running SAST scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            # Log outputs
            if result.stdout:
                sanitized_stdout = re.sub(r"opengrep", "[scanner]", result.stdout, flags=re.IGNORECASE)
                Logger.get_logger().debug(sanitized_stdout)
                if "--help" in (self.command or ""):
                    Logger.log_with_color("INFO", sanitized_stdout, Fore.WHITE)
                    return config.PASS_RETURN_CODE, None

            if result.stderr:
                sanitized_stderr = re.sub(r"opengrep", "[scanner]", result.stderr, flags=re.IGNORECASE)
                if "--help" in (self.command or "") and result.returncode == 0:
                    Logger.log_with_color("INFO", sanitized_stderr, Fore.WHITE)
                    return config.PASS_RETURN_CODE, None
                else:
                    Logger.get_logger().error(sanitized_stderr)


            if os.path.exists(self.result_file) and os.stat(self.result_file).st_size > 0:
                self._fix_file_permissions_if_docker()
                self.process_result_file()
                if self._severity_threshold_met():
                    Logger.get_logger().error(f"Vulnerabilities matching severities: {', '.join(self.severity)} found.")
                    return 1, self.result_file
                return 0, self.result_file
            else:
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during SAST scan: {e}")
            raise

    def _build_sast_args(self):
        """
        Sanitize raw OpenGrep args:
        - Remove conflicting --json / --output flags
        - Ensure -f (rules directory) is set, defaulting to /rules/default-rules/
        - Append enforced output flags
        """
        args = shlex.split(self.command or "")
        forbidden_flags = {"--json", "--output"}
        sanitized_args = []
        i = 0
        saw_rules_flag = False

        while i < len(args):
            if args[i] in forbidden_flags:
                # skip the flag and its value if it requires one
                if args[i] == "--output":
                    i += 2
                    continue
                else:
                    i += 1
                    continue

            if args[i] == "-f":
                saw_rules_flag = True
                sanitized_args.append(args[i])
                if i + 1 < len(args):
                    sanitized_args.append(args[i + 1])
                    i += 2
                    continue

            sanitized_args.append(args[i])
            i += 1

        # Ensure rules path (-f) is set
        if not self.container_mode:
            sast_binary = ToolManager.get_path("sast")
        default_rules = "/rules/default-rules/" if self.container_mode else ToolManager.get_path("sast-rules")
        if not saw_rules_flag:
            sanitized_args.extend(["-f", default_rules])

        # Enforce output format
        sanitized_args.extend([
            "--json",
            "--output", self.result_file,
        ])

        return sanitized_args
        
        
    def _fix_file_permissions_if_docker(self):
        if self.container_mode:
            try:
                chmod_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{os.getcwd()}:/app",
                    "--entrypoint", "bash",
                    self.opengrep_image,
                    "-c", f"chmod 777 {self.result_file}"
                ]
                subprocess.run(chmod_cmd, capture_output=True, text=True)
            except Exception as e:
                Logger.get_logger().debug(f"Could not fix file permissions: {e}")

    def process_result_file(self):
        try:
            # Load existing JSON
            with open(self.result_file, 'r') as file:
                data = json.load(file)

            # Ensure data is a dict
            if not isinstance(data, dict):
                Logger.get_logger().debug("Expected a dict at root; taking the first element if list.")
                if isinstance(data, list) and data:
                    data = data[0]
                else:
                    data = {}

            path = urlparse(self.repo_url).path  # e.g., /org/repo.git
            repo_name = os.path.basename(path).replace(".git", "")

            # Merge metadata into root
            data.update({
                "repo": repo_name,
                "sha": self.commit_sha,
                "ref": self.commit_ref,
                "run_id": self.pipeline_id,
                "repo_url": self.repo_url,
                "repo_run_url": self.job_url
            })

            # Write back
            with open(self.result_file, 'w') as file:
                json.dump(data, file, indent=2)

            Logger.get_logger().debug("Result file processed successfully.")

        except Exception as e:
            Logger.get_logger().debug(f"Error processing result file: {e}")
            Logger.get_logger().error(f"Error during IaC scan: {e}")
            raise



    def _build_sast_command(self, args):
        """
        Construct the full command (local or Docker).
        """
        if not self.container_mode:
            cmd = [ToolManager.get_path("sast")]
        else:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.getcwd()}:/app",
                self.opengrep_image,
            ]

        cmd.extend(args)
        return cmd

    def _severity_threshold_met(self):
        try:
            with open(self.result_file, 'r') as f:
                data = json.load(f)

            # Ensure "results" exists
            results = data.get("results", [])
            for result in results:
                # Extract severity from extra
                severity = result.get("extra", {}).get("severity", "").upper()
                if severity in self.severity:
                    return True
            return False

        except Exception as e:
            Logger.get_logger().error(f"Error reading scan results: {e}")
            raise