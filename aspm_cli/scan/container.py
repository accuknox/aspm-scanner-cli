import subprocess
import json
import os
import shlex
from aspm_cli.utils.logger import Logger
from aspm_cli.utils import docker_pull
from aspm_cli.utils import config
from colorama import Fore
from aspm_cli.utils.policy import policy_threshold_triggered

class ContainerScanner:
    ak_container_image = "aquasec/trivy:0.62.1"
    result_file = './results.json'

    def __init__(self, command, non_container_mode=False):
        self.command = command
        self.non_container_mode = non_container_mode

    def run(self):
        try:
            if not self.non_container_mode:
                docker_pull(self.ak_container_image)

            severity_threshold, sanitized_args = self._build_container_scan_args()
            scan_cmd = self._build_scan_command(sanitized_args)

            Logger.get_logger().debug(f"Scanning container image: {' '.join(scan_cmd)}")
            result = subprocess.run(scan_cmd, capture_output=True, text=True)

            if result.stdout:
                sanitized_stdout = result.stdout.replace("trivy", "[scanner]")
                Logger.get_logger().debug(sanitized_stdout)
                if("--help" in self.command):
                    Logger.log_with_color('INFO', sanitized_stdout, Fore.WHITE)
                    return config.PASS_RETURN_CODE, None
            if result.stderr:
                sanitized_stderr = result.stderr.replace("trivy", "[scanner]")
                Logger.get_logger().error(sanitized_stderr)

            if not os.path.exists(self.result_file):
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

            severity_threshold = [s.strip().upper() for s in (severity_threshold or "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL").split(',')]
            if self._severity_threshold_met():
                # Logger.get_logger().error(f"Vulnerabilities matching severities: {', '.join(severity_threshold)} found.")
                return 1, self.result_file
            print(self._severity_threshold_met())
            return 0, self.result_file
        except Exception as e:
            Logger.get_logger().error(f"Error during container scan: {e}")
            raise

    def _build_container_scan_args(self):
        """
        Parses the raw command, strips forbidden arguments, and enforces
        the required output format and file. This ensures the class can
        reliably find the JSON output.
        """
        # Flags that take a value and should be removed.
        flags_to_strip = {"-s", "--severity", "-o", "--output", "-f", "--format", "--exit-code", "--quiet"}
        severity_threshold = None

        # Use shlex to handle quotes and spaces correctly
        original_args = shlex.split(self.command)
        sanitized_args = []
        
        i = 0
        while i < len(original_args):
            arg = original_args[i]
            # If the arg is a flag to strip, skip it and its value
            if arg in flags_to_strip:
                if arg in ("-s", "--severity"):
                    if i + 1 < len(original_args):
                        severity_threshold = original_args[i + 1]
                i += 2
                continue
            
            sanitized_args.append(arg)
            i += 1

        sanitized_args.extend(["--quiet", "--exit-code", "1", "-f", "json", "-o", self.result_file])
        return severity_threshold, sanitized_args
    
    def _build_scan_command(self, container_scan_args):
        if self.non_container_mode:
            cmd = (['trivy'])
        else:
            cmd = [
                "docker", "run", "--rm",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", f"{os.getcwd()}:/workdir",
                "--workdir", "/workdir",
                self.ak_container_image,
            ]
        
        cmd.extend(container_scan_args)
        return cmd

    def _severity_threshold_met(self):
        try:
            with open(self.result_file, 'r') as f:
                data = json.load(f)

            findings = []

            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    findings.append({
                        "severity": vuln.get("Severity", "")
                    })

            return policy_threshold_triggered(findings)

        except Exception as e:
            Logger.get_logger().error(f"Error reading scan results: {e}")
            raise