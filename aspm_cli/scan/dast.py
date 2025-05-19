import subprocess
import json
import os
from aspm_cli.utils import docker_pull
from aspm_cli.utils.logger import Logger


class DASTScanner:
    zap_image = "zaproxy/zap-stable:2.16.1"
    result_file = "report.json"

    def __init__(self, target_url=None, severity_threshold=None, scan_type=None):
        self.target_url = target_url
        self.severity_threshold = severity_threshold
        self.scan_type = scan_type

    def run(self):
        try:
            docker_pull(self.zap_image)
            Logger.get_logger().debug("Starting ZAP DAST scan...")

            zap_command = (
                f"zap-baseline.py -t {self.target_url} -J {self.result_file} -I"
                if self.scan_type == "baseline"
                else f"zap-full-scan.py -t {self.target_url} -J {self.result_file} -I"
            )
            print(zap_command)

            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.getcwd()}:/zap/wrk:rw",
                "-t", self.zap_image,
                zap_command
            ]

            Logger.get_logger().debug(f"Running DAST scan: {' '.join(cmd)}")
            result = subprocess.run(" ".join(cmd), shell=True, capture_output=True, text=True)

            if result.stdout:
                Logger.get_logger().debug(result.stdout)
            if result.stderr:
                Logger.get_logger().error(result.stderr)

            exit_code = self.evaluate_results()
            return exit_code, self.result_file

        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during DAST scan: {e}")
            raise

    def evaluate_results(self):
        risk_map = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
        risk_code = risk_map.get(self.severity_threshold, 3)

        try:
            with open(self.result_file, 'r') as f:
                zap_results = json.load(f)

            alerts = [
                alert for site in zap_results.get("site", [])
                for alert in site.get("alerts", [])
                if int(alert["riskcode"]) >= risk_code
            ]

            if alerts:
                Logger.get_logger().error(
                    f"Found vulnerabilities with severity {self.severity_threshold} or higher."
                )
                return 1
            else:
                Logger.get_logger().info(
                    f"No vulnerabilities with severity {self.severity_threshold} or higher found."
                )
                return 0

        except Exception as e:
            Logger.get_logger().error(f"Error evaluating DAST results: {e}")
            return 1
