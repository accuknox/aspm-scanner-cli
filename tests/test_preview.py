import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from aspm_cli import cli


def run_cli(argv, env):
    out = io.StringIO()
    with patch.dict(os.environ, env, clear=True), patch.object(sys, "argv", ["accuknox-aspm-scanner", *argv]), \
            patch("aspm_cli.cli.print_banner"), redirect_stdout(out):
        try:
            cli.main()
            code = 0
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue()


class PreviewHelpTests(unittest.TestCase):
    def test_top_level_help_hides_decorate_pr(self):
        code, out = run_cli(["--help"], {})
        self.assertEqual(code, 0)
        self.assertNotIn("decorate-pr", out)
        self.assertIn("pipeline", out)

    def test_top_level_help_lists_decorate_pr_with_preview(self):
        _, out = run_cli(["--help"], {"ACCUKNOX_PREVIEW": "true"})
        self.assertIn("decorate-pr", out)
        self.assertIn("[preview]", out)

    def test_changed_only_hidden_from_pipeline_and_scan_help(self):
        for argv in (["pipeline", "--help"], ["scan", "--help"]):
            _, out = run_cli(argv, {})
            self.assertNotIn("--changed-only", out, argv)
            self.assertNotIn("--base-ref", out, argv)
            _, out = run_cli(argv, {"ACCUKNOX_PREVIEW": "1"})
            self.assertIn("--changed-only", out, argv)
            self.assertIn("[preview]", out, argv)

    def test_changed_only_still_parses_without_preview(self):
        """A pipeline that still passes the flag must not break: it gets a full scan instead."""
        from aspm_cli.commands.pipeline_command import PipelineCommand
        import argparse
        parser = argparse.ArgumentParser()
        with patch.dict(os.environ, {}, clear=True):
            PipelineCommand().configure_parser(parser)
        args = parser.parse_args(["--scans", "sast", "--changed-only", "--base-ref", "main"])
        self.assertTrue(args.changed_only)


class DecoratePrPreviewTests(unittest.TestCase):
    def test_refused_without_preview(self):
        with patch("aspm_cli.commands.pr_decorator_command.pr_decorator_run.run") as run, \
                patch("aspm_cli.utils.logger.Logger.get_logger") as logger:
            code, _ = run_cli(["decorate-pr", "--result-file", "r.json"], {})
        self.assertEqual(code, 1)
        run.assert_not_called()
        self.assertIn("ACCUKNOX_PREVIEW=true", logger.return_value.error.call_args.args[0])

    def test_runs_with_preview(self):
        with patch("aspm_cli.commands.pr_decorator_command.pr_decorator_run.run", return_value=0) as run:
            code, _ = run_cli(["decorate-pr", "--result-file", "r.json", "--dry-run"], {"ACCUKNOX_PREVIEW": "true"})
        self.assertEqual(code, 0)
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
