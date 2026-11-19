import argparse
import os

import pytest

from aspm_cli.commands import pipeline_command, scan_command
from aspm_cli.commands.pipeline_command import PipelineCommand
from aspm_cli.commands.scan_command import ScanCommand
from aspm_cli.utils import quality_gate as qg
from aspm_cli.utils import scan_runner
from aspm_cli.utils.scan_runner import ScanRun

CLI_ID = "469c1037-2983-4438-9d73-a2384f805a40"
IDENTITY = {"repo_url": "https://github.com/acme/api", "branch": "main", "commit_sha": "a" * 40}
DATA_TYPES = {"SAST": "SG", "SCA": "TR", "SECRET": "TruffleHog", "IAC": "IAC", "SQ-SAST": "SQ", "CONTAINER": "SBOM"}


class Harness:
    """Replaces the scanners, the upload and the poll with scripted stand-ins."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp_path = tmp_path
        self.exit_codes = {}     # registry key -> scanner exit code (default 0)
        self.no_result = set()   # registry keys that write no result file
        self.crash = set()       # registry keys whose scanner raises
        self.upload_fails = set()  # data types whose upload fails
        self.uploads = []        # (data_type, params, file existed when uploaded)
        self.scan_args = {}      # registry key -> the Namespace the scanner was run with
        self.poll_result = qg.GateResult("resolved", {"ready": True, "status": "passed", "message": "ok"})
        self.polled = []

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ACCUKNOX_CLI_ID", CLI_ID)
        for name in ("ACCUKNOX_QUALITY_GATE", "SOFT_FAIL", "KEEP_RESULTS", "ACCUKNOX_REPOSITORY"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(scan_runner, "run_scan", self.run_scan)
        monkeypatch.setattr(pipeline_command, "run_scan", self.run_scan)
        monkeypatch.setattr(scan_command, "run_scan", self.run_scan)
        monkeypatch.setattr(scan_runner, "upload_results", self.upload_results)
        monkeypatch.setattr(pipeline_command, "collect_ingest_identity", lambda: dict(IDENTITY))
        monkeypatch.setattr(scan_command, "collect_ingest_identity", lambda: dict(IDENTITY))
        monkeypatch.setattr(pipeline_command, "poll_gate", self.poll_gate)
        monkeypatch.setattr(pipeline_command, "report", lambda *a, **k: None)

    def run_scan(self, args, accuknox_config, softfail, skip_upload):
        key = args.scantype
        self.scan_args[key] = args
        if key in self.crash:
            raise RuntimeError(f"{key} blew up")
        result_file = None
        if key not in self.no_result:
            result_file = str(self.tmp_path / "results.json")  # every scanner writes the same name
            is_sbom = key == "CONTAINER" and getattr(args, "generate_sbom", False)
            with open(result_file, "w") as handle:
                handle.write('{"components": [{"name": "left-pad"}]}' if is_sbom else f'{{"from": "{key}"}}')
        is_sbom = key == "CONTAINER" and getattr(args, "generate_sbom", False)
        return ScanRun(key, DATA_TYPES[key], self.exit_codes.get(key, 0), result_file, is_sbom=is_sbom)

    def upload_results(self, file_path, endpoint, label, token, tenant, data_type, keep_file=False, extra_params=None):
        with open(file_path) as handle:
            self.uploads.append((data_type, dict(extra_params or {}), handle.read()))
        if not keep_file:
            os.remove(file_path)
        return 1 if data_type in self.upload_fails else 0

    def poll_gate(self, config, cli_id, timeout):
        self.polled.append((cli_id, timeout))
        return self.poll_result


@pytest.fixture
def harness(tmp_path, monkeypatch):
    return Harness(tmp_path, monkeypatch)


def pipeline_args(**overrides):
    parser = argparse.ArgumentParser()
    PipelineCommand().configure_parser(parser)
    args = parser.parse_args(["--scans", "sast", "--endpoint", "e.example.com", "--label", "L", "--token", "t"])
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def run_pipeline(harness, **overrides):
    with pytest.raises(SystemExit) as exit_info:
        PipelineCommand().execute(pipeline_args(**overrides))
    return exit_info.value.code


# ---------------------------------------------------------------- pipeline


def test_uploads_every_scan_with_the_run_and_declares_exactly_those(harness):
    code = run_pipeline(harness, scans="sast,sca,iac,secret", quality_gate=True)
    assert code == 0
    assert [upload[0] for upload in harness.uploads] == ["SG", "TR", "IAC", "TruffleHog"]
    for _, params, _ in harness.uploads:
        assert params["cli_id"] == CLI_ID
        assert params["scanners"] == "SG,TR,IAC,TruffleHog"
        assert params["repository"] == "acme/api" and params["branch"] == "main"
    assert harness.polled == [(CLI_ID, 300)]


def test_each_scan_result_is_kept_apart_although_scanners_share_a_file_name(harness):
    run_pipeline(harness, scans="sast,sca,iac", quality_gate=True)
    assert [upload[2] for upload in harness.uploads] == ['{"from": "SAST"}', '{"from": "SCA"}', '{"from": "IAC"}']


def test_a_scan_without_results_is_not_declared_so_the_gate_cannot_hang(harness):
    harness.no_result.add("SECRET")
    code = run_pipeline(harness, scans="sast,secret", quality_gate=True)
    assert code == 0
    assert [upload[0] for upload in harness.uploads] == ["SG"]
    assert harness.uploads[0][1]["scanners"] == "SG"


def test_nothing_to_evaluate_means_no_poll(harness):
    harness.no_result.update({"SAST", "SECRET"})
    assert run_pipeline(harness, scans="sast,secret", quality_gate=True) == 0
    assert harness.uploads == [] and harness.polled == []


def test_findings_do_not_fail_the_scan_step_but_the_policy_verdict_does(harness):
    harness.exit_codes = {"SAST": 1, "SECRET": 183}
    harness.poll_result = qg.GateResult(
        "resolved", {"ready": True, "status": "failed", "blocking": True, "message": "Gate failed: SG"}
    )
    assert run_pipeline(harness, scans="sast,secret", quality_gate=True) == 1
    harness.poll_result = qg.GateResult("resolved", {"ready": True, "status": "passed", "message": "ok"})
    assert run_pipeline(harness, scans="sast,secret", quality_gate=True) == 0  # findings alone no longer fail


def test_softfail_relaxes_only_the_policy_failure(harness):
    harness.poll_result = qg.GateResult(
        "resolved", {"ready": True, "status": "failed", "blocking": True, "message": "x"}
    )
    assert run_pipeline(harness, scans="sast", quality_gate=True, softfail=True) == 0


def test_a_failed_upload_stops_the_poll_and_fails(harness):
    harness.upload_fails.add("TR")
    assert run_pipeline(harness, scans="sast,sca", quality_gate=True) == 2
    assert harness.polled == []


def test_a_scan_that_cannot_run_fails_the_build_even_if_the_gate_passes(harness):
    harness.crash.add("SCA")
    assert run_pipeline(harness, scans="sast,sca", quality_gate=True) == 2
    assert [upload[0] for upload in harness.uploads] == ["SG"]  # the others still ran and were gated
    assert harness.polled  # ... and their verdict was still shown


def test_sast_exit_2_stays_a_failure_in_gate_mode(harness):
    harness.exit_codes = {"SAST": 2}  # scanner or AI analysis failed
    assert run_pipeline(harness, scans="sast", quality_gate=True) == 2


def test_gate_timeout_follows_on_timeout(harness):
    harness.poll_result = qg.GateResult("timeout", {}, "")
    assert run_pipeline(harness, scans="sast", quality_gate=True, gate_timeout=30) == 2
    assert harness.polled == [(CLI_ID, 30)]
    assert run_pipeline(harness, scans="sast", quality_gate=True, gate_on_timeout="pass") == 0


def test_without_the_gate_it_is_plain_sequential_scanning(harness):
    harness.exit_codes = {"IAC": 1}
    assert run_pipeline(harness, scans="sast,iac") == 1
    assert [upload[0] for upload in harness.uploads] == ["SG", "IAC"]
    assert "cli_id" not in harness.uploads[0][1] and harness.polled == []
    assert run_pipeline(harness, scans="sast,iac", softfail=True) == 0


def test_bad_options_are_rejected_before_any_scan_runs(harness):
    assert run_pipeline(harness, scans="sast,zap") == 2
    assert run_pipeline(harness, scans="sq-sast") == 2  # needs --sq-sast-command
    assert run_pipeline(harness, scans="sast", quality_gate=True, skip_upload=True) == 2
    assert harness.uploads == []


def test_missing_repository_fails_fast_instead_of_hanging_the_gate(harness, monkeypatch):
    monkeypatch.setattr(pipeline_command, "collect_ingest_identity", lambda: {})
    assert run_pipeline(harness, scans="sast", quality_gate=True) == 2
    assert harness.uploads == [] and harness.polled == []


def test_an_empty_sbom_is_skipped_not_declared(harness, monkeypatch):
    original = harness.run_scan

    def empty_sbom(args, *rest):
        run = original(args, *rest)
        with open(run.result_file, "w") as handle:
            handle.write("{}")
        return run

    monkeypatch.setattr(pipeline_command, "run_scan", empty_sbom)
    assert run_pipeline(harness, scans="sast,sbom", quality_gate=True) == 0
    assert [upload[0] for upload in harness.uploads] == ["SG"]
    assert harness.uploads[0][1]["scanners"] == "SG"  # the empty SBOM is not declared, so the gate cannot wait on it


def test_sbom_runs_as_a_container_sbom(harness):
    assert run_pipeline(harness, scans="sbom", quality_gate=True) == 0
    assert harness.uploads[0][0] == "SBOM" and harness.uploads[0][1]["scanners"] == "SBOM"


# ------------------------------------------------------------ AI analysis


def test_ai_analysis_is_off_unless_the_flag_is_given(harness):
    assert run_pipeline(harness, scans="sast,iac") == 0
    assert harness.scan_args["SAST"].ai_analysis is None  # undecided: the scanner's own default (off) applies


def test_ai_flag_turns_it_on_for_sast_with_its_options(harness):
    code = run_pipeline(
        harness, scans="sast,iac,sca", ai_analysis=True, aiscan_severity="HIGH,CRITICAL",
        codeassure_config="/cfg/codeassure.json", graph_no_joern=True,
    )
    assert code == 0
    sast = harness.scan_args["SAST"]
    assert sast.ai_analysis is True and sast.aiscan_severity == "HIGH,CRITICAL"
    assert sast.codeassure_config == "/cfg/codeassure.json" and sast.graph_no_joern is True
    assert not hasattr(harness.scan_args["IAC"], "ai_analysis")  # scans without an AI step are untouched


def test_ai_options_need_the_ai_flag(harness):
    assert run_pipeline(harness, scans="sast", aiscan_severity="HIGH") == 2
    assert harness.scan_args == {}


def test_ai_flag_with_no_ai_capable_scan_warns_but_runs(harness, caplog):
    assert run_pipeline(harness, scans="iac,sca", ai_analysis=True) == 0
    assert "--ai-analysis has no effect" in caplog.text


# ------------------------------------------------------- scanner arg parsing


def test_scanner_args_reuse_each_scanners_own_defaults():
    sast = scan_runner.scanner_args("SAST", ["--command", "scan ."])
    assert sast.command == "scan ." and sast.severity.startswith("LOW") and sast.scantype == "SAST"
    secret = scan_runner.scanner_args("SECRET", ["--command", "filesystem .", "--engine", "gitleaks"])
    assert secret.engine == "gitleaks"
    with pytest.raises(ValueError, match="sast"):
        scan_runner.scanner_args("SAST", [])


# --------------------------------------------------------- scan --quality-gate


def scan_args(scantype="SAST", **overrides):
    parser = argparse.ArgumentParser()
    ScanCommand().configure_parser(parser)
    argv = ["--endpoint", "e.example.com", "--label", "L", "--token", "t", scantype.lower(), "--command", "scan ."]
    args = parser.parse_args(argv)
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def run_scan_command(**overrides):
    """Exit code of `scan` (a clean run returns without calling sys.exit)."""
    try:
        ScanCommand().execute(scan_args(**overrides))
    except SystemExit as exit_info:
        return exit_info.code or 0
    return 0


def test_scan_with_gate_declares_the_run_and_ignores_findings(harness):
    harness.exit_codes = {"SAST": 1}
    assert run_scan_command(quality_gate=True, gate_scanners="SG,TR") == 0
    (data_type, params, _), = harness.uploads
    assert data_type == "SG" and params["cli_id"] == CLI_ID and params["scanners"] == "SG,TR"


def test_scan_adds_its_own_type_to_the_declared_set(harness):
    run_scan_command(quality_gate=True, gate_scanners="TR")
    assert harness.uploads[0][1]["scanners"] == "TR,SG"


def test_scan_without_gate_is_unchanged(harness):
    harness.exit_codes = {"SAST": 1}
    assert run_scan_command() == 1
    assert "cli_id" not in harness.uploads[0][1]


def test_scan_gate_needs_declared_scanners_and_an_upload(harness):
    assert run_scan_command(quality_gate=True) == 2
    assert run_scan_command(quality_gate=True, gate_scanners="SG", skip_upload=True) == 2
    assert harness.uploads == []
