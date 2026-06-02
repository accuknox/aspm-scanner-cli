import unittest
from unittest.mock import patch

from aspm_cli.scan.sast import SASTScanner


class TestSASTContainerModeCommand(unittest.TestCase):
    def test_build_sast_command_sets_workdir_for_docker(self):
        scanner = SASTScanner(
            command="scan .",
            container_mode=True,
            severity="LOW,MEDIUM,HIGH,CRITICAL",
            ai_analysis=False,
        )

        with patch("aspm_cli.scan.sast.os.getcwd", return_value="/tmp/workdir"):
            cmd = scanner._build_sast_command(["scan", ".", "--json", "--output", "results.json"])

        self.assertEqual(
            cmd[:7],
            ["docker", "run", "--rm", "-v", "/tmp/workdir:/app", "-w", "/app"],
        )

    def test_fix_permissions_uses_app_workdir(self):
        scanner = SASTScanner(
            command="scan .",
            container_mode=True,
            severity="LOW,MEDIUM,HIGH,CRITICAL",
            ai_analysis=False,
        )

        with patch("aspm_cli.scan.sast.os.getcwd", return_value="/tmp/workdir"), patch(
            "aspm_cli.scan.sast.subprocess.run"
        ) as run_mock:
            scanner._fix_file_permissions_if_docker()

        run_args = run_mock.call_args[0][0]
        self.assertIn("-w", run_args)
        self.assertIn("/app", run_args)


if __name__ == "__main__":
    unittest.main()
