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
    codeassure_image = os.getenv("CODEASSURE_IMAGE", "public.ecr.aws/k9v9d5v2/accuknox/ai-sast-codeassure-cli:0.1.1")
    result_file = "results.json"

    def __init__(self, command=None, container_mode=True, severity = None,
                 repo_url=None, commit_ref=None, commit_sha=None,
                 pipeline_id=None, job_url=None, ai_analysis=True, codeassure_config=None,aiscan_severity=None):
        """
        :param command: Raw OpenGrep CLI args (string)
        :param container_mode: Run in Docker if True, else use local binary
        :param repo_url: Git repository URL
        :param commit_ref: Branch or ref
        :param commit_sha: Commit SHA
        :param pipeline_id: CI pipeline ID
        :param job_url: CI job URL
        :param ai_analysis: Enable AI analysis of results
        """
        self.command = command
        self.container_mode = container_mode
        self.severity = [s.strip().upper() for s in (severity).split(',')]
        self.aiscan_severity = [s.strip().upper() for s in aiscan_severity.split(',')] if ai_analysis and isinstance(aiscan_severity, str) else []
        self.repo_url = repo_url
        self.commit_ref = commit_ref
        self.commit_sha = commit_sha
        self.pipeline_id = pipeline_id
        self.job_url = job_url
        self.ai_analysis = ai_analysis
        self.codeassure_config = codeassure_config

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

                # Run AI analysis if enabled (before checking severity threshold)
                if self.ai_analysis:
                    try:
                        Logger.get_logger().debug("Starting AI analysis of SAST results...")
                        self._run_ai_analysis()
                        self._apply_verification_fields()
                    except Exception as e:
                        Logger.get_logger().error(f"AI analysis failed: {e}")

                # Check severity threshold and return appropriate exit code
                if self._severity_threshold_met():
                    Logger.get_logger().error(f"Vulnerabilities matching severities: {', '.join(self.severity)} found.")
                    return 1, self.result_file
                return 0, self.result_file
            else:
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during SAST scan: {e}")
            raise


    def _run_ai_analysis(self):
        """
        Runs AI analysis on the results. If any error occurs, the original results are preserved.
        This ensures the scan continues successfully even if AI analysis fails.
        """
        try:
            if self.container_mode:
                docker_pull(self.codeassure_image)
            else:
                ToolManager.get_path("codeassure")  # raises FileNotFoundError if not installed

            # Check if there are any results to analyze
            with open(self.result_file, 'r') as f:
                current_data = json.load(f)

            results = current_data.get("results", [])
            Logger.get_logger().info(f"Running AI analysis: {len(results)} findings to analyze.")
            
            if not results or len(results) == 0:
                Logger.get_logger().debug("No results to analyze. Skipping AI analysis.")
                return


            cmd = self._build_ai_analysis_command()
 
            ai_result = subprocess.run(cmd, check=False)

            if ai_result.returncode != 0:
                Logger.get_logger().warning(f"AI analysis failed with exit code: {ai_result.returncode}. Continuing with original results.")
                return

        except Exception as e:
            Logger.get_logger().warning(f"Unexpected error during AI analysis: {e}. Continuing with original results.")
            Logger.get_logger().debug(f"Exception details: {str(e)}")

        return
    
    def _apply_verification_fields(self):
        """
        After codeassure writes verification data, promote is_false_positive
        and validation_reason to the top level of each finding.
        """
        try:
            with open(self.result_file, 'r') as f:
                data = json.load(f)

            for finding in data.get("results", []):
                verification = finding.get("verification", {})
                is_vuln = verification.get("is_security_vulnerability")
                finding["is_false_positive"] = not bool(is_vuln) if is_vuln is not None else None
                finding["validation_reason"] = verification.get("reason")
                finding["severity_by_ai"] = verification.get("severity").upper() if verification.get("severity") else None

            with open(self.result_file, 'w') as f:
                json.dump(data, f, indent=2)

            Logger.get_logger().debug("Verification fields applied to results.")
        except Exception as e:
            Logger.get_logger().warning(f"Could not apply verification fields: {e}")

    def validate_updated_results(self, results):
        if not isinstance(results, dict) or "results" not in results:
            raise ValueError("AI analysis output is not in the expected format.")

    
    def _build_ai_analysis_command(self) -> list[str]:
        """
        Build the AI Analysis CLI command (local or Docker).

        :return: List of command arguments
        """

        if not self.container_mode:
            cmd = [
                ToolManager.get_path("codeassure"),
                "--codebase", os.getcwd(),
                "--findings", self.result_file,
                "--output", self.result_file,
            ]
            if self.codeassure_config:
                cmd.extend(["--config", self.codeassure_config])
            if self.aiscan_severity:
                cmd.extend(["--severity", ",".join(self.aiscan_severity)])

        else:
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.getcwd()}:/workspace",
            ]
            if self.codeassure_config:
                config_path = os.path.abspath(self.codeassure_config)
            elif os.path.exists(os.path.join(os.getcwd(), "codeassure.json")):
                config_path = os.path.join(os.getcwd(), "codeassure.json")
            else:
                config_path = None
            if config_path:
                cmd.extend(["-v", f"{config_path}:/app/codeassure.json"])
                try:
                    with open(config_path) as _f:
                        _cfg = json.load(_f)
                    _raw_key = _cfg.get("model", {}).get("api_key")
                    if _raw_key:
                        if _raw_key.startswith("$"):
                            env_var_name = _raw_key[1:]
                            api_key_val = os.environ.get(env_var_name)
                        if api_key_val:
                            cmd.extend(["-e", f"{env_var_name}={api_key_val}"])
                except Exception:
                    pass

            cmd.extend([
                self.codeassure_image,
                "--codebase", "/workspace",
                "--findings", "/workspace/results.json",
                "--output", "/workspace/results.json",
            ])
            if self.aiscan_severity:
                cmd.extend(["--severity", ",".join(self.aiscan_severity)])


        return cmd    

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
                    "-w", "/app",
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

            # Extract repo name from URL or use directory name as fallback
            if self.repo_url and self.repo_url.strip():
                try:
                    path = urlparse(self.repo_url).path  # e.g., /org/repo.git
                    repo_name = os.path.basename(path).replace(".git", "")
                except Exception as e:
                    raise ValueError(f"Invalid repository URL format: {self.repo_url}. Error: {e}")
            else:
                # Fallback: Use directory name when Git is not available
                repo_name = os.path.basename(os.getcwd())
                self.repo_url = f"localhost/{repo_name}"  
                Logger.get_logger().info(f"Git not available, using directory name '{repo_name}' as repo identifier")

            # Merge metadata into root
            metadata = {
                "repo": repo_name,
                "sha": self.commit_sha,
                "ref": self.commit_ref,
                "run_id": self.pipeline_id,
                "repo_url": self.repo_url,
                "repo_run_url": self.job_url,
                "ai_analysis": self.ai_analysis
            }
            data.update(metadata)

            # Write back
            with open(self.result_file, 'w') as file:
                json.dump(data, file, indent=2)

            Logger.get_logger().debug("Result file processed successfully.")

        except Exception as e:
            Logger.get_logger().debug(f"Error processing result file: {e}")
            Logger.get_logger().error(f"Error during SAST scan: {e}")
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
                "-w", "/app",
                self.opengrep_image,
            ]

        cmd.extend(args)
        return cmd

    def _severity_threshold_met(self):
        try:
            with open(self.result_file, 'r') as f:
                data = json.load(f)

            # OpenGrep reports severities as ERROR/WARNING/INFO; normalize them
            # to the standard scale so user-supplied severities (e.g. HIGH) match.
            severity_map = {
                "ERROR": "HIGH",
                "WARNING": "MEDIUM",
                "INFO": "LOW",
            }

            results = data.get("results", [])
            for result in results:
                severity = result.get("extra", {}).get("severity", "").upper()
                normalized_severity = severity_map.get(severity, severity)
                if normalized_severity in self.severity:
                    return True
            return False

        except Exception as e:
            Logger.get_logger().error(f"Error reading scan results: {e}")
            raise