import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from aspm_cli.scan.container import ContainerScanner


class ContainerSbomPermissionTests(unittest.TestCase):
    def _run(self, container_mode):
        with tempfile.TemporaryDirectory() as directory:
            result = os.path.join(directory, "results.json")
            open(result, "w").write("{}")
            scanner = ContainerScanner("image alpine:3.18", container_mode=container_mode, generate_sbom=True)
            scanner.result_file = result
            completed = MagicMock(returncode=0, stdout="", stderr="")
            with patch("aspm_cli.scan.container.subprocess.run", return_value=completed), \
                 patch("aspm_cli.scan.container.docker_pull"), \
                 patch("aspm_cli.scan.container._fix_result_file_permissions_if_docker") as fix:
                code, path = scanner.run()
            return code, path, result, fix

    def test_container_mode_hands_result_file_back_before_enrichment(self):
        code, path, result, fix = self._run(True)
        self.assertEqual((code, path), (0, result))
        fix.assert_called_once_with(True, result)

    def test_local_mode_passes_container_flag_false(self):
        _, _, result, fix = self._run(False)
        fix.assert_called_once_with(False, result)


if __name__ == "__main__":
    unittest.main()
