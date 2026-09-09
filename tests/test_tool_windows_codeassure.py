import os
import unittest
from unittest.mock import patch

from aspm_cli.tool.download import (
    CODEASSURE_WINDOWS_ASSET,
    WINDOWS_SUPPORTED_TOOLS,
    ToolDownloader,
)


class TestWindowsCodeassureInstall(unittest.TestCase):
    def test_codeassure_is_a_windows_local_tool(self):
        self.assertIn("codeassure", WINDOWS_SUPPORTED_TOOLS)

    def test_windows_url_default(self):
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("CODEASSURE_WINDOWS_URL", "CODEASSURE_WINDOWS_RELEASE")
        }
        with patch.dict(os.environ, env, clear=True):
            url = ToolDownloader.codeassure_windows_url()
        self.assertTrue(url.endswith(CODEASSURE_WINDOWS_ASSET))
        self.assertIn("/releases/latest/download/", url)

    def test_windows_url_pinned_release(self):
        env = dict(os.environ)
        env.pop("CODEASSURE_WINDOWS_URL", None)
        env["CODEASSURE_WINDOWS_RELEASE"] = "v0.15.0"
        with patch.dict(os.environ, env, clear=True):
            url = ToolDownloader.codeassure_windows_url()
        self.assertIn("/releases/download/v0.15.0/", url)

    def test_windows_url_env_override(self):
        with patch.dict(
            os.environ,
            {"CODEASSURE_WINDOWS_URL": "https://example.local/codeassure.exe"},
            clear=False,
        ):
            self.assertEqual(
                ToolDownloader.codeassure_windows_url(),
                "https://example.local/codeassure.exe",
            )
