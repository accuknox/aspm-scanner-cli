import subprocess
import json
import os
from aspm_cli.utils import docker_pull

from aspm_cli.utils.logger import Logger

class SASTScanner:
    opengrep_image = "accuknox/opengrepjob:1.0.1"
    result_file = f'results.json'

    def __init__(self, repo_url=None, commit_ref=None, commit_sha=None, pipeline_id=None, job_url=False):
        self.repo_url = repo_url
        self.commit_ref = commit_ref
        self.commit_sha = commit_sha
        self.pipeline_id = pipeline_id
        self.job_url = job_url

    def run(self):
        try:
            docker_pull(self.opengrep_image)
            Logger.get_logger().debug("Starting OpenGrep scan...")

            cmd = [
                "docker", "run", "--rm",
                "-v", f"{os.getcwd()}:/app",
                "-e", f"REPOSITORY_URL={self.repo_url}",
                "-e", f"COMMIT_SHA={self.commit_sha}",
                "-e", f"COMMIT_REF={self.commit_ref}",
                "-e", f"PIPELINE_ID={self.pipeline_id}",
                "-e", f"JOB_URL={self.job_url}",
                f"{self.opengrep_image}"
            ]

            Logger.get_logger().debug(f"Running OpenGrep scan: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            if(result.stdout):
                Logger.get_logger().debug(result.stdout)
            if(result.stderr):
                Logger.get_logger().error(result.stderr)

            exit_code = result.returncode
            return exit_code, self.result_file
        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during SAST scan: {e}")
            raise