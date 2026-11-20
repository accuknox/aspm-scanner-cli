import os
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aspm_cli.utils import tls


class DownloadContextTests(unittest.TestCase):
    def setUp(self):
        tls.download_context.cache_clear()
        self.addCleanup(tls.download_context.cache_clear)

    def test_has_cas_even_without_system_ones(self):
        """The frozen macOS binary has no system CAs: certifi's must still be loaded."""
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": "/nonexistent", "SSL_CERT_DIR": "/nonexistent"}):
            context = tls.download_context()
        self.assertGreater(context.cert_store_stats()["x509_ca"], 0)

    def test_verification_stays_on(self):
        context = tls.download_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


class DownloadsUseTheContextTests(unittest.TestCase):
    def test_tool_download_passes_the_context(self):
        from aspm_cli.tool import download

        response = mock.MagicMock()
        response.__enter__.return_value.read.side_effect = [b"data", b""]
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(download.urllib.request, "urlopen", return_value=response) as urlopen:
            downloader = download.ToolDownloader.__new__(download.ToolDownloader)
            downloader._download_file("https://example.invalid/tool.tar.gz", Path(tmp) / "tool.tar.gz")
        self.assertIs(urlopen.call_args.kwargs["context"], tls.download_context())

    def test_ai_sast_and_syft_downloads_pass_the_context(self):
        from aspm_cli.tool import ai_sast, syft

        for module in (ai_sast, syft):
            source = Path(module.__file__).read_text()
            self.assertIn("context=download_context()", source, module.__name__)


if __name__ == "__main__":
    unittest.main()
