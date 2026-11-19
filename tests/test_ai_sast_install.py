import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aspm_cli.tool import ai_sast


def _release(system="Linux", machine="x86_64", corrupt=None, omit=None):
    suffix = ".exe" if system == "Windows" else ""
    target = {"Linux": "linux-amd64", "Darwin": "darwin-arm64", "Windows": "windows-amd64"}[system]
    files = {f"{tool}-{target}{suffix}": f"binary-of-{tool}".encode() for tool in ai_sast.TOOLS}
    sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in files.items() if name != omit)
    if corrupt:
        files[corrupt] = b"tampered"
    files[ai_sast.SUMS_NAME] = sums.encode()
    return files


class AiSastInstallTests(unittest.TestCase):
    def _install(self, files, system="Linux", machine="x86_64"):
        def fake_download(url):
            return files[url.rsplit("/", 1)[1]]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ai_sast.platform, "system", return_value=system), \
                patch.object(ai_sast.platform, "machine", return_value=machine), \
                patch.object(ai_sast, "_download", side_effect=fake_download):
            ok = ai_sast.install_ai_sast(directory)
            found = sorted(p.name for p in (Path(directory) / "codeassure").glob("*")) if ok or (Path(directory) / "codeassure").exists() else []
        return ok, found

    def test_installs_both_binaries_side_by_side(self):
        self.assertEqual(self._install(_release()), (True, ["codeassure", "context-graph"]))

    def test_windows_names_get_exe(self):
        self.assertEqual(self._install(_release("Windows"), "Windows", "AMD64"), (True, ["codeassure.exe", "context-graph.exe"]))

    def test_a_checksum_mismatch_installs_nothing(self):
        self.assertEqual(self._install(_release(corrupt="context-graph-linux-amd64")), (False, []))

    def test_a_binary_missing_from_the_checksum_file_is_refused(self):
        self.assertEqual(self._install(_release(omit="codeassure-linux-amd64")), (False, []))

    def test_unsupported_platform_is_refused(self):
        self.assertEqual(self._install(_release(), "Linux", "aarch64"), (False, []))


if __name__ == "__main__":
    unittest.main()
