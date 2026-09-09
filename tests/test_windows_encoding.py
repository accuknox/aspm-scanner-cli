import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aspm_cli.scan.sast import SASTScanner
from aspm_cli.utils.subprocess_utils import run_scan_subprocess, utf8_text


class TestUtf8Subprocess(unittest.TestCase):
    def test_cp1252_rejects_opengrep_utf8_bytes(self):
        # U+201D encodes as e2 80 9d; 0x9d is undefined in Windows cp1252.
        utf8_bytes = "Use \u201dquotes\u201d".encode("utf-8")
        self.assertIn(0x9D, utf8_bytes)
        with self.assertRaises(UnicodeDecodeError):
            utf8_bytes.decode("cp1252")

    def test_utf8_text_decodes_bytes_cp1252_cannot(self):
        snippet = "finding \u201d"
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(sys.argv[1].encode('utf-8'))",
                snippet,
            ],
            capture_output=True,
            **utf8_text(),
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("finding", proc.stdout)

    def test_run_scan_subprocess_passes_utf8_encoding(self):
        completed = subprocess.CompletedProcess(["echo"], 0, "ok", "")
        with patch("aspm_cli.utils.subprocess_utils.subprocess.run", return_value=completed) as mock_run:
            run_scan_subprocess(["echo", "hi"])
        kwargs = mock_run.call_args.kwargs
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "replace")
        self.assertTrue(kwargs["text"])


class TestSastUtf8Results(unittest.TestCase):
    def test_process_result_file_reads_utf8_smart_quotes(self):
        scanner = SASTScanner(
            command=".",
            container_mode=False,
            ai_analysis=False,
            repo_url="https://dev.azure.com/org/Harshitha/_git/Harshitha",
        )
        payload = {
            "results": [
                {
                    "check_id": "rule",
                    "extra": {
                        "message": "Do not use \u201cpassword\u201d",
                        "metadata": {"impact": "HIGH"},
                    },
                }
            ]
        }
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                with open("results.json", "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, ensure_ascii=False)
                scanner.process_result_file()
                with open("results.json", encoding="utf-8") as handle:
                    data = json.load(handle)
            finally:
                os.chdir(cwd)

        self.assertEqual(data["repo"], "Harshitha")
        self.assertIn("password", data["results"][0]["extra"]["message"])

    @patch("aspm_cli.scan.sast.ToolManager.get_path", return_value="opengrep")
    @patch("aspm_cli.scan.sast.subprocess.run")
    def test_run_decodes_opengrep_output_as_utf8(self, mock_run, _get_path):
        mock_run.return_value = subprocess.CompletedProcess(["opengrep"], 0, "", "")
        scanner = SASTScanner(command=".", container_mode=False, ai_analysis=False)
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                with open("results.json", "w", encoding="utf-8") as handle:
                    json.dump({"results": []}, handle)
                scanner.run()
            finally:
                os.chdir(cwd)

        kwargs = mock_run.call_args.kwargs
        self.assertEqual(kwargs.get("encoding"), "utf-8")
        self.assertEqual(kwargs.get("errors"), "replace")


if __name__ == "__main__":
    unittest.main()
