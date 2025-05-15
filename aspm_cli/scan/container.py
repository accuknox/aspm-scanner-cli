import subprocess
import json
import os
import shlex
from aspm_cli.utils.logger import Logger
from aspm_cli.utils import docker_pull

class ContainerScanner:
    trivy_image = "aquasec/trivy:0.62.1"
    result_file = './results.json'

    def __init__(self, image_name, tag=None, severity=None, base_command=None):
        self.image_name = image_name
        self.tag = tag
        self.severity = [s.strip().upper() for s in (severity or "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL").split(',')]
        self.base_command = base_command

    def run(self):
        try:
            if not self.base_command:
                docker_pull(self.trivy_image)

            scan_cmd = self._build_scan_command()

            Logger.get_logger().debug(f"Scanning container image: {' '.join(scan_cmd)}")
            result = subprocess.run(scan_cmd, capture_output=True, text=True)

            if result.stdout:
                Logger.get_logger().debug(result.stdout)
            if result.stderr:
                Logger.get_logger().error(result.stderr)

            if not os.path.exists(self.result_file):
                Logger.get_logger().info("No results found. Skipping upload.")
                return 0, None

            if self._severity_threshold_met():
                Logger.get_logger().error(f"Vulnerabilities matching severities: {', '.join(self.severity)} found.")
                return 1, self.result_file

            return 0, self.result_file
        except Exception as e:
            Logger.get_logger().error(f"Error during container scan: {e}")
            raise

    def _build_scan_command(self):
        if self.base_command:
            cmd = shlex.split(self.base_command)
        else:
            cmd = [
                "docker", "run", "--rm",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", f"{os.getcwd()}:/workdir",
                "--workdir", "/workdir",
                self.trivy_image,
            ]

        cmd.extend([
            "image", "--exit-code", "1", "-f", "json",
            f"{self.image_name}:{self.tag}",
            "-o", self.result_file,
            "--quiet"
        ])

        return cmd

    def _severity_threshold_met(self):
        try:
            with open(self.result_file, 'r') as f:
                data = json.load(f)

            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    if vuln.get("Severity", "").upper() in self.severity:
                        return True
            return False
        except Exception as e:
            Logger.get_logger().error(f"Error reading scan results: {e}")
            raise
