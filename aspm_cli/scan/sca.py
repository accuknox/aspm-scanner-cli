from aspm_cli.scan.trivy_runner import run_trivy_vuln_scan, validate_sca_command


class SCAScanner:
    result_file = "./results.json"

    def __init__(
        self,
        command,
        container_mode=False,
        severity=None,
        repo_url=None,
        repo_branch=None,
    ):
        self.command = command
        self.container_mode = container_mode
        self.severity = severity
        self.repo_url = repo_url
        self.repo_branch = repo_branch

    def run(self):
        return run_trivy_vuln_scan(
            self.command,
            self.container_mode,
            self.result_file,
            validate_command=validate_sca_command,
            cli_severity=self.severity,
            sca_mode=True,
            repo_url=self.repo_url,
            repo_branch=self.repo_branch,
        )
