import json
import uuid

import pytest
import requests

from aspm_cli.utils import quality_gate as qg
from aspm_cli.utils.ingest_identity import derive_repository

CONFIG = {"accuknox_endpoint": "cspm.example.com", "accuknox_token": "t", "accuknox_tenant": "2"}
CLI_ID = "469c1037-2983-4438-9d73-a2384f805a40"


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.text = str(self._body)

    def json(self):
        return self._body


class Clock:
    """Deterministic time: sleeping advances it."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def poll(responses, timeout=300):
    """poll_gate against a scripted sequence of responses (an exception instance is raised)."""
    clock, queue, calls = Clock(), list(responses), []

    def http_get(url, **kwargs):
        calls.append((url, kwargs))
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return item

    result = qg.poll_gate(CONFIG, CLI_ID, timeout=timeout, http_get=http_get, sleep=clock.sleep, clock=clock.monotonic)
    return result, calls, clock


def ready(status, **extra):
    return FakeResponse(200, {"ready": True, "status": status, "message": "m", **extra})


PENDING = FakeResponse(200, {"ready": False, "status": "pending", "pending": ["SG"], "message": "Waiting on: SG"})


# ------------------------------------------------------------------ cli_id


def test_explicit_cli_id_wins_and_is_validated():
    assert qg.resolve_cli_id(CLI_ID.upper(), env={"GITHUB_RUN_ID": "1"}) == CLI_ID
    assert qg.resolve_cli_id(None, env={"ACCUKNOX_CLI_ID": CLI_ID}) == CLI_ID
    with pytest.raises(qg.GateConfigError):
        qg.resolve_cli_id("not-a-uuid", env={})


def test_ci_runs_derive_a_stable_id_shared_by_every_step():
    env = {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": "acme/api"}
    first = qg.resolve_cli_id(None, env=env)
    assert first == qg.resolve_cli_id(None, env=dict(env))
    assert uuid.UUID(first)
    # a re-run (new attempt) or another run is a different gate run
    assert first != qg.resolve_cli_id(None, env={**env, "GITHUB_RUN_ATTEMPT": "2"})
    assert first != qg.resolve_cli_id(None, env={**env, "GITHUB_RUN_ID": "43"})


def test_outside_ci_ids_are_random():
    assert qg.resolve_cli_id(None, env={}) != qg.resolve_cli_id(None, env={})


# ------------------------------------------------------------ upload params


def test_repository_is_derived_from_the_url():
    assert derive_repository("https://github.com/varendra007/kubearmor.git") == "varendra007/kubearmor"
    assert derive_repository("git@gitlab.com:group/sub/proj.git") == "group/sub/proj"
    assert derive_repository("https://user:tok@github.com/acme/api") == "acme/api"
    assert derive_repository("github.com/acme/api") == "acme/api"
    assert derive_repository("/Users/me/local/repo") == ""
    assert derive_repository("") == ""


def test_gate_params_carry_run_scanners_and_repository(monkeypatch):
    monkeypatch.delenv("ACCUKNOX_REPOSITORY", raising=False)
    identity = {"repo_url": "https://github.com/acme/api", "branch": "main", "commit_sha": "a" * 40}
    params = qg.gate_upload_params(CLI_ID, "SG, TR,SG", identity)
    assert params == {**identity, "cli_id": CLI_ID, "scanners": "SG,TR", "repository": "acme/api"}
    assert qg.gate_upload_params(CLI_ID, ["IAC"], identity, repository="org/other")["repository"] == "org/other"


def test_gate_params_fail_fast_without_repository_or_branch(monkeypatch):
    monkeypatch.delenv("ACCUKNOX_REPOSITORY", raising=False)
    with pytest.raises(qg.GateConfigError, match="repository and branch"):
        qg.gate_upload_params(CLI_ID, "SG", {})
    with pytest.raises(qg.GateConfigError, match="branch"):
        qg.gate_upload_params(CLI_ID, "SG", {"repo_url": "https://github.com/acme/api"})


def test_scanners_must_be_gated_types():
    with pytest.raises(qg.GateConfigError, match="ZAP"):
        qg.normalize_scanners("SG,ZAP")
    with pytest.raises(qg.GateConfigError):
        qg.normalize_scanners("")


# --------------------------------------------------------------------- poll


def test_polls_until_ready_with_backoff_and_auth():
    result, calls, clock = poll([PENDING, PENDING, ready("passed")])
    assert result.state == "resolved" and len(calls) == 3
    url, kwargs = calls[0]
    assert url == "https://cspm.example.com/api/v1/cicd/scan-status/"
    assert kwargs["params"] == {"cli_id": CLI_ID}
    assert kwargs["headers"] == {"Authorization": "Bearer t", "Tenant-Id": "2"}
    assert clock.sleeps == sorted(clock.sleeps) and max(clock.sleeps) <= qg.MAX_POLL_INTERVAL


def test_connection_errors_and_5xx_are_retried():
    result, calls, _ = poll([requests.ConnectionError("down"), FakeResponse(503), ready("passed")])
    assert result.state == "resolved" and len(calls) == 3


def test_a_late_run_is_found_after_a_few_404s():
    result, calls, _ = poll([FakeResponse(404), FakeResponse(404), ready("passed")])
    assert result.state == "resolved" and len(calls) == 3


def test_persistent_404_means_unsupported_backend():
    result, calls, _ = poll([FakeResponse(404)])
    assert result.state == "unsupported" and len(calls) == qg.NOT_FOUND_LIMIT
    assert "does not support quality gates" in result.detail
    assert qg.decide(result) == qg.EXIT_OPERATIONAL


def test_the_gate_token_is_used_for_the_poll_when_given():
    config = {**CONFIG, "accuknox_gate_token": "user-token"}
    clock, calls = Clock(), []
    qg.poll_gate(config, CLI_ID, http_get=lambda url, **kw: calls.append(kw) or ready("passed"),
                 sleep=clock.sleep, clock=clock.monotonic)
    assert calls[0]["headers"]["Authorization"] == "Bearer user-token"


def test_a_rejected_upload_token_points_at_the_gate_token():
    result, _, _ = poll([FakeResponse(403, {"detail": "Token contained no recognizable user identification"})])
    assert result.state == "rejected"
    assert "ACCUKNOX_GATE_TOKEN" in result.detail and "no recognizable user" in result.detail


def test_auth_errors_are_final():
    result, calls, _ = poll([FakeResponse(401, {"detail": "bad token"})])
    assert result.state == "rejected" and len(calls) == 1 and "bad token" in result.detail
    assert qg.decide(result) == qg.EXIT_OPERATIONAL


def test_timeout_keeps_the_last_pending_payload():
    result, calls, clock = poll([PENDING], timeout=30)
    assert result.state == "timeout" and result.payload["pending"] == ["SG"]
    assert clock.now <= 30


# ------------------------------------------------------------------ verdict


def resolved(status, **extra):
    return qg.GateResult("resolved", {"ready": True, "status": status, "message": "m", **extra})


def test_passed_and_warning_do_not_fail_the_build():
    assert qg.decide(resolved("passed")) == qg.EXIT_PASS
    assert qg.decide(resolved("warning", warnings=True)) == qg.EXIT_PASS


def test_policy_failure_fails_the_build_unless_softfail():
    failed = resolved("failed", blocking=True, overall_scan_status="policy_failed")
    assert qg.decide(failed) == qg.EXIT_POLICY_FAILED
    assert qg.decide(failed, softfail=True) == qg.EXIT_PASS


def test_blocking_flag_is_honoured_even_if_status_reads_passed():
    assert qg.decide(resolved("passed", blocking=True)) == qg.EXIT_POLICY_FAILED


def test_scans_that_could_not_be_evaluated_fail_even_with_softfail():
    failures = [{"scanner": "SG", "code": "policy_service_unavailable", "reason": "policy-service is unavailable"}]
    unavailable = resolved("failed", blocking=True, failures=failures)
    assert qg.decide(unavailable, softfail=True) == qg.EXIT_OPERATIONAL
    assert qg.decide(resolved("error", blocking=True), softfail=True) == qg.EXIT_OPERATIONAL


def test_timeout_follows_the_on_timeout_choice():
    timeout = qg.GateResult("timeout", {}, "HTTP 503")
    assert qg.decide(timeout) == qg.EXIT_OPERATIONAL
    assert qg.decide(timeout, on_timeout="pass") == qg.EXIT_PASS
    assert qg.decide(timeout, softfail=True) == qg.EXIT_OPERATIONAL


def test_summary_lists_scanners_breaches_and_the_verdict():
    result = resolved(
        "failed",
        blocking=True,
        message="Gate failed: SG",
        results={
            "SG": {
                "status": "fail",
                "counts": {"critical": 0, "high": 13, "medium": 122, "low": 206},
                "reasons": [{"policy": "default-gate", "action": "block", "param": "high", "found": 13, "threshold": 2}],
            },
            "TR": {"status": "pass", "counts": {"critical": 0, "high": 0, "medium": 1, "low": 0}, "reasons": []},
        },
    )
    text = "\n".join(qg.summary_lines(result, qg.EXIT_POLICY_FAILED))
    assert "SG         FAIL     C:0 H:13 M:122 L:206" in text
    assert "default-gate [block]: high found 13 > threshold 2" in text
    assert "TR         PASS" in text
    assert text.splitlines()[-1] == "Quality gate failed: Gate failed: SG"


def test_a_compliance_breach_is_described_without_a_threshold():
    reason = {"policy": "p", "action": "block", "param": "compliance", "framework": "owasp-top-10",
              "found": 7, "categories": ["A01:2021", "A03:2021"]}
    assert qg._reason_line(reason) == "p [block]: owasp-top-10: 7 findings (A01:2021, A03:2021)"


def test_softfail_still_reports_the_gate_as_failed():
    result = resolved("failed", blocking=True, message="Gate failed: SG", results={})
    last = qg.summary_lines(result, qg.EXIT_PASS, softfail=True)[-1]
    assert last == "Quality gate failed (soft fail: not blocking the build): Gate failed: SG"


def test_a_failure_code_is_not_repeated_as_a_note():
    failures = [{"scanner": "SG", "code": "policy_service_unavailable", "reason": "policy-service is unavailable"}]
    result = resolved(
        "failed", blocking=True, failures=failures,
        results={"SG": {"status": "fail", "counts": {}, "reasons": [], "note": "policy_service_unavailable"}},
    )
    lines = qg.summary_lines(result, qg.EXIT_OPERATIONAL)
    assert not any(line.strip() == "- policy_service_unavailable" for line in lines)
    assert "SG: policy-service is unavailable" in lines


def test_report_writes_github_summary_and_annotation(tmp_path, monkeypatch, capsys):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    result = resolved("failed", blocking=True, message="Gate failed: SG", results={})
    qg.report(result, qg.EXIT_POLICY_FAILED)
    assert "::error title=AccuKnox quality gate::Quality gate failed: Gate failed: SG" in capsys.readouterr().out
    assert "### AccuKnox quality gate" in summary.read_text()


def test_report_prints_the_backend_response_as_json_and_can_save_it(tmp_path, capsys):
    payload = {"ready": True, "status": "failed", "blocking": True, "message": "Gate failed: SG", "results": {}}
    out = tmp_path / "gate.json"
    qg.report(resolved("failed", **{k: v for k, v in payload.items() if k not in ("ready", "status", "message")}),
              qg.EXIT_POLICY_FAILED, cli_id=CLI_ID, json_file=str(out))
    printed = capsys.readouterr().out
    body = printed.split("-----\n", 1)[1].rsplit("\n-----", 1)[0]
    document = json.loads(body)
    assert document["cli_id"] == CLI_ID and document["exit_code"] == 1 and document["state"] == "resolved"
    assert document["response"]["status"] == "failed" and document["response"]["blocking"] is True
    assert json.loads(out.read_text()) == document


def test_json_is_printed_for_a_timeout_without_a_response(capsys):
    qg.report(qg.GateResult("timeout", {}, "no verdict in 300s"), qg.EXIT_OPERATIONAL, cli_id=CLI_ID)
    body = capsys.readouterr().out.split("-----\n", 1)[1].rsplit("\n-----", 1)[0]
    document = json.loads(body)
    assert document["state"] == "timeout" and document["response"] == {} and document["detail"] == "no verdict in 300s"
