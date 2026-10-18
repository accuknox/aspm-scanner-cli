import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from aspm_cli.scan.sast import SASTScanner
from aspm_cli.scanners.sast_scanner import SASTScanner as Strategy


class AiSastTests(unittest.TestCase):
    def test_default_and_explicit_opt_out_take_precedence_over_environment(self):
        parser = argparse.ArgumentParser()
        Strategy().add_arguments(parser)
        for env, flags, enabled in [("", [], True), ("FALSE", [], False),
                                     ("TRUE", ["--no-ai-analysis"], False),
                                     ("FALSE", ["--ai-analysis"], True)]:
            with self.subTest(env=env, flags=flags), patch.dict(os.environ, {"ACCUKNOX_ENABLE_AI_SAST": env}), patch("aspm_cli.scanners.sast_scanner.OriginalSASTScanner") as factory:
                Strategy().run_scan(parser.parse_args(["--command", "scan .", *flags]))
                self.assertEqual(factory.call_args.kwargs["ai_analysis"], enabled)

    def test_best_practice_is_not_a_false_positive_and_fallback_is_not_a_verdict(self):
        data = {"results": [{"verification": {"verdict": verdict,
                  "is_security_vulnerability": False, "severity": "low", "analysis_status": status}}
                  for verdict, status in [("true_positive", "completed"), ("false_positive", "completed"), ("false_positive", "fallback"), ("uncertain", "completed")]]}
        SASTScanner._promote_verification_fields(data)
        self.assertEqual([r["is_false_positive"] for r in data["results"]], [False, True, None, None])
        self.assertNotIn("severity_by_ai", data["results"][2])

    def test_ai_process_failure_preserves_base_report_and_returns_operational_error(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = SASTScanner(container_mode=False)
            scanner.result_file = str(Path(directory) / "results.json")
            def scan(*args, **kwargs):
                Path(scanner.result_file).write_text(json.dumps({"results": [{"check_id": "r", "extra": {"metadata": {"impact": "HIGH"}}}]}))
                return subprocess.CompletedProcess([], 0, "", "")
            with patch.object(scanner, "_build_sast_args", return_value=[]), patch.object(scanner, "_build_sast_command", return_value=["scanner"]), patch("aspm_cli.scan.sast.subprocess.run", side_effect=scan), patch.object(scanner, "_run_ai_analysis", side_effect=RuntimeError("provider unavailable")):
                code, report = scanner.run()
            data = json.loads(Path(report).read_text())
            self.assertEqual(code, 2)
            self.assertEqual(len(data["results"]), 1)
            self.assertEqual(data["ai_sast"]["status"], "failed")
            self.assertFalse(data["ai_analysis"])

    def test_container_environment_passes_secret_names_without_values(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"model": {"api_key": "$AI_TEST_KEY"}, "validator": {"api_key": "$VALIDATOR_TEST_KEY"}}))
            scanner = SASTScanner(codeassure_config=str(config), container_mode=True)
            with patch.dict(os.environ, {"AI_TEST_KEY": "secret-value", "VALIDATOR_TEST_KEY": "validator-value"}):
                command = scanner._build_ai_analysis_command(Path.cwd() / "verified.json")
            self.assertIn("AI_TEST_KEY", command)
            self.assertIn("VALIDATOR_TEST_KEY", command)
            self.assertNotIn("secret-value", " ".join(command))

    def test_scanner_error_never_uploads_stale_results(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = SASTScanner(container_mode=False, ai_analysis=False)
            scanner.result_file = str(Path(directory) / "results.json")
            Path(scanner.result_file).write_text('{"results": []}')
            with patch.object(scanner, "_build_sast_args", return_value=[]), patch.object(scanner, "_build_sast_command", return_value=["scanner"]), patch("aspm_cli.scan.sast.subprocess.run", return_value=subprocess.CompletedProcess([], 7, "", "error")):
                self.assertEqual(scanner.run(), (2, None))
            self.assertFalse(Path(scanner.result_file).exists())
