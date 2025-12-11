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
    claude_image = os.getenv("CLAUDE_IMAGE", "esh279/claude-cli:latest")
    result_file = "results.json"

    def __init__(self, command=None, container_mode=True, severity = None,
                 repo_url=None, commit_ref=None, commit_sha=None,
                 pipeline_id=None, job_url=None, antropic_api_key=None, ai_analysis=False):
        """
        :param command: Raw OpenGrep CLI args (string)
        :param container_mode: Run in Docker if True, else use local binary
        :param repo_url: Git repository URL
        :param commit_ref: Branch or ref
        :param commit_sha: Commit SHA
        :param pipeline_id: CI pipeline ID
        :param job_url: CI job URL
        :param antropic_api_key: Anthropic API key for AI analysis
        :param ai_analysis: Enable AI analysis of results
        """
        self.command = command
        self.container_mode = container_mode
        self.severity = [s.strip().upper() for s in (severity or "").split(',')] if severity else []
        self.repo_url = repo_url
        self.commit_ref = commit_ref
        self.commit_sha = commit_sha
        self.pipeline_id = pipeline_id
        self.job_url = job_url
        self.antropic_api_key = antropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        self.ai_analysis = ai_analysis

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
                    except Exception as e:
                        Logger.get_logger().error(f"AI analysis failed: {e}")

                # Check severity threshold and return appropriate exit code
                if self._severity_threshold_met():
                    Logger.get_logger().error(f"Vulnerabilities matching severities: {', '.join(self.severity)} found.")
                    return 1, self.result_file

                Logger.get_logger().debug("SAST scan completed successfully with no matching vulnerabilities.")
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
            if not self.antropic_api_key:
                Logger.get_logger().warning("Anthropic API key not provided. Skipping AI analysis.")
                return

            # Check if there are any results to analyze
            with open(self.result_file, 'r') as f:
                current_data = json.load(f)

            results = current_data.get("results", [])
            Logger.get_logger().debug(f"Running Claude AI analysis: {len(results)} findings to analyze.")
            
            if not results or len(results) == 0:
                Logger.get_logger().debug("No results to analyze. Skipping AI analysis.")
                return

            if self.container_mode:
                docker_pull(self.claude_image)

            cmd = self._build_claude_command()
            Logger.get_logger().debug(f"Running Claude AI analysis: {' '.join(cmd[:5])}...")
            ai_result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if ai_result.stderr:
                Logger.get_logger().debug(f"Claude analysis errors: {ai_result.stderr}")

            if ai_result.returncode != 0:
                Logger.get_logger().warning(f"AI analysis failed with exit code: {ai_result.returncode}. Continuing with original results.")
                return

            if not ai_result.stdout:
                Logger.get_logger().warning("AI analysis returned empty output. Continuing with original results.")
                return

            # Extract JSON from Claude's output (remove markdown code blocks if present)
            output = ai_result.stdout.strip()
            print(f"[DEBUG] Raw AI output length: {len(output)}")
            print(f"[DEBUG] First 200 chars: {output[:200]}")

            # Try to extract JSON from markdown code blocks
            if "```json" in output:
                json_start = output.find("```json") + 7
                json_end = output.find("```", json_start)
                output = output[json_start:json_end].strip()
                print(f"[DEBUG] Extracted from ```json block")
            elif "```" in output:
                json_start = output.find("```") + 3
                json_end = output.find("```", json_start)
                output = output[json_start:json_end].strip()
                print(f"[DEBUG] Extracted from ``` block")

            # Try to find JSON object/array if there's extra text
            if not output.startswith('{') and not output.startswith('['):
                json_start = min(
                    output.find('{') if '{' in output else len(output),
                    output.find('[') if '[' in output else len(output)
                )
                if json_start < len(output):
                    output = output[json_start:]
                    print(f"[DEBUG] Found JSON start at position {json_start}")

            # Parse the AI output
            updated_results = json.loads(output)
            Logger.get_logger().debug(f"Parsed AI analysis output successfully{updated_results}.")

            # Validate the structure
            if not isinstance(updated_results, dict) or "results" not in updated_results:
                Logger.get_logger().warning("AI analysis output missing 'results' field. Continuing with original results.")
                return

            # Preserve metadata fields that were added by process_result_file
            metadata_fields = ['repo', 'sha', 'ref', 'run_id', 'repo_url', 'repo_run_url']
            for field in metadata_fields:
                if field in current_data:
                    updated_results[field] = current_data[field]

            # Write the updated results
            with open(self.result_file, 'w') as f:
                json.dump(updated_results, f, indent=2)

            print(f"[DEBUG] AI analysis completed successfully - added analysis to {len(updated_results.get('results', []))} findings")
            Logger.get_logger().debug("AI analysis completed successfully and results updated.")

        except json.JSONDecodeError as e:
            Logger.get_logger().warning(f"Failed to parse Claude output as JSON: {e}. Continuing with original results.")
            Logger.get_logger().debug(f"Raw output: {ai_result.stdout[:500] if 'ai_result' in locals() else 'N/A'}...")
        except FileNotFoundError as e:
            Logger.get_logger().warning(f"Result file not found during AI analysis: {e}. Continuing without AI analysis.")
        except Exception as e:
            Logger.get_logger().warning(f"Unexpected error during AI analysis: {e}. Continuing with original results.")
            Logger.get_logger().debug(f"Exception details: {str(e)}")

        return
    
    def validate_updated_results(self, results):
        if not isinstance(results, dict) or "results" not in results:
            raise ValueError("AI analysis output is not in the expected format.")

        # for item in results["results"]:
        #     if "is_false_positive" not in item or "validation_reason" not in item:
        #         raise ValueError("Missing required fields in AI analysis results.")
    
    def _build_claude_command(self) -> list[str]:
        """
        Build the Claude CLI command (local or Docker).

        :return: List of command arguments
        """

        system_prompt = """You are a security analysis expert. Your task is to analyze SAST findings and determine if they are real vulnerabilities or false positives.

For each finding, you must:
1. Read the source code file at the given path
2. Examine the code at the specified line numbers
3. Determine if it's a real security vulnerability or false positive
4. Consider: input validation, framework protections, code context, exploitability

Output ONLY valid JSON with the same structure as input, adding these two fields to each result:
- "is_false_positive": boolean (true if safe code, false if real vulnerability)
- "validation_reason": string (brief explanation)"""

        user_prompt = """Read the file /workspace/results.json and analyze each security finding.

Add the two new fields (is_false_positive and validation_reason) to EACH item in the "results" array.

Return the COMPLETE JSON structure with all original fields preserved and the two new fields added.

Output ONLY the JSON object - no markdown blocks, no explanations, no additional text."""

        if not self.container_mode:
            cmd = ["claude", "--system-prompt", system_prompt, user_prompt]
        else:
            cmd = [
                "docker", "run", "--rm",
                "-e", f"ANTHROPIC_API_KEY={self.antropic_api_key}",
                "-e", "CLAUDE_CODE_MAX_OUTPUT_TOKENS=200000",
                "-v", f"{os.getcwd()}:/workspace",
                self.claude_image,
                "claude", "--system-prompt", system_prompt, user_prompt
            ]

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