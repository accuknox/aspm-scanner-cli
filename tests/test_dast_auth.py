"""
Self-check for ZAP browser-based auth support in DASTScanner.
Plain asserts, no framework: `python tests/test_dast_auth.py`.
"""
import os
import sys
import tempfile

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aspm_cli.scan.dast import DASTScanner
from aspm_cli.utils.config import ConfigValidator


def _render_plan(scanner, args, full_scan=False):
    cwd = os.getcwd()
    tmp = tempfile.mkdtemp()
    os.chdir(tmp)
    try:
        scanner._write_auth_plan(args, full_scan)
        with open(scanner.auth_plan_file) as f:
            return yaml.safe_load(f)
    finally:
        os.chdir(cwd)


def test_no_auth_command_untouched():
    scanner = DASTScanner("zap-baseline.py -t https://example.com")
    sanitized = scanner._build_dast_args(["-t", "https://example.com"], is_recognized_script=True)
    assert sanitized.count("-J") == 1
    assert "--hook" not in sanitized


def test_api_scan_gets_json_report_enforced():
    scanner = DASTScanner("zap-api-scan.py -t openapi.json -f openapi -O https://example.com")
    sanitized = scanner._build_dast_args(
        ["-t", "openapi.json", "-f", "openapi", "-O", "https://example.com"],
        is_recognized_script=True,
    )
    assert sanitized[-2:] == ["-J", "results.json"]


def test_auth_requires_baseline_or_full_scan_command():
    scanner = DASTScanner(
        "zap.sh -cmd", container_mode=True,
        auth_url="https://example.com/login", auth_username="alice", auth_password="s3cret",
    )
    try:
        scanner._check_automation_supported(is_baseline_or_full=False)
        assert False, "expected ValueError for non baseline/full-scan command"
    except ValueError:
        pass


def test_auth_requires_container_mode():
    scanner = DASTScanner(
        "zap-baseline.py -t https://example.com", container_mode=False,
        auth_url="https://example.com/login", auth_username="alice", auth_password="s3cret",
    )
    try:
        scanner._check_automation_supported(is_baseline_or_full=True)
        assert False, "expected NotImplementedError for non-container mode"
    except NotImplementedError:
        pass


def test_auth_plan_uses_browser_auth_and_target():
    scanner = DASTScanner(
        "zap-baseline.py -t https://juice-shop.example.com", container_mode=True,
        auth_url="https://juice-shop.example.com/#/login",
        auth_username="admin@juice-sh.op", auth_password="admin123",
    )
    plan = _render_plan(scanner, ["-t", "https://juice-shop.example.com"])
    ctx = plan["env"]["contexts"][0]
    assert ctx["authentication"]["method"] == "browser"
    assert ctx["authentication"]["parameters"]["loginPageUrl"] == scanner.auth_url
    assert ctx["users"][0]["credentials"] == {"username": "admin@juice-sh.op", "password": "admin123"}
    assert ctx["sessionManagement"] == {"method": "cookie"}
    job_types = [j["type"] for j in plan["jobs"]]
    assert job_types == ["spider", "passiveScan-wait", "report"]


def test_auth_plan_full_scan_adds_active_scan_job():
    scanner = DASTScanner(
        "zap-full-scan.py -t https://example.com", container_mode=True,
        auth_url="https://example.com/login", auth_username="u", auth_password="p",
    )
    plan = _render_plan(scanner, ["-t", "https://example.com"], full_scan=True)
    assert [j["type"] for j in plan["jobs"]] == ["spider", "passiveScan-wait", "activeScan", "report"]


def test_auth_plan_session_management_always_cookie():
    scanner = DASTScanner(
        "zap-baseline.py -t https://example.com", container_mode=True,
        auth_url="https://example.com/#/login", auth_username="u", auth_password="p",
    )
    plan = _render_plan(scanner, ["-t", "https://example.com"])
    assert plan["env"]["contexts"][0]["sessionManagement"] == {"method": "cookie"}


def test_auth_plan_verification_with_fallback_url():
    scanner = DASTScanner(
        "zap-baseline.py -t https://example.com", container_mode=True,
        auth_url="https://example.com/#/login", auth_username="u", auth_password="p",
        auth_login_fallback_url="https://example.com/rest/user/whoami",
        auth_logged_in_regex=r"\Quser@example.com\E",
        auth_logged_out_regex=r"\Qguest\E",
    )
    plan = _render_plan(scanner, ["-t", "https://example.com"])
    verification = plan["env"]["contexts"][0]["authentication"]["verification"]
    assert verification["method"] == "poll"
    assert verification["pollUrl"] == scanner.auth_login_fallback_url
    assert verification["loggedInRegex"] == scanner.auth_logged_in_regex
    assert verification["loggedOutRegex"] == scanner.auth_logged_out_regex


def test_auth_plan_verification_without_fallback_url_uses_response():
    scanner = DASTScanner(
        "zap-baseline.py -t https://example.com", container_mode=True,
        auth_url="https://example.com/#/login", auth_username="u", auth_password="p",
        auth_logged_in_regex=r"\Quser@example.com\E",
    )
    plan = _render_plan(scanner, ["-t", "https://example.com"])
    verification = plan["env"]["contexts"][0]["authentication"]["verification"]
    assert verification["method"] == "response"
    assert "pollUrl" not in verification


def test_auth_plan_no_verification_block_when_no_regex_given():
    scanner = DASTScanner(
        "zap-baseline.py -t https://example.com", container_mode=True,
        auth_url="https://example.com/#/login", auth_username="u", auth_password="p",
    )
    plan = _render_plan(scanner, ["-t", "https://example.com"])
    assert "verification" not in plan["env"]["contexts"][0]["authentication"]


def test_report_job_targets_result_file():
    scanner = DASTScanner(
        "zap-baseline.py -t https://example.com", container_mode=True,
        auth_url="https://example.com/login", auth_username="u", auth_password="p",
    )
    plan = _render_plan(scanner, ["-t", "https://example.com"])
    report = [j for j in plan["jobs"] if j["type"] == "report"][0]["parameters"]
    assert report["template"] == "traditional-json"
    assert report["reportFile"] == "results"


_CTFLEARN_PLAN = """
env:
  contexts:
  - name: target-context
    urls:
    - 'https://ctflearn.com/'
    includePaths:
    - 'https://ctflearn.com/.*'
  parameters:
    failOnError: true
    failOnWarning: false
    progressToStdout: true
jobs:
- type: passiveScan-config
  name: passiveScan-config
  parameters:
    disableAllRules: false
    scanOnlyInScope: true
  rules: []
- type: spider
  name: SpiderAsUser
  parameters:
    context: target-context
    maxDuration: 10
    maxChildren: 50
    maxDepth: 5
- type: spiderAjax
  name: spiderAjax
  parameters:
    context: target-context
    inScopeOnly: true
    maxDuration: 10
- type: passiveScan-wait
  name: Wait for Passive Scan
  parameters:
    maxDuration: 5
"""


def _write_user_plan(scanner, plan_yaml):
    cwd = os.getcwd()
    tmp = tempfile.mkdtemp()
    os.chdir(tmp)
    try:
        plan_path = os.path.join(tmp, "zap.yaml")
        with open(plan_path, "w") as f:
            f.write(plan_yaml)
        scanner.plan_file = plan_path
        scanner._write_user_plan()
        with open(scanner.auth_plan_file) as f:
            return yaml.safe_load(f)
    finally:
        os.chdir(cwd)


def test_user_plan_unauth_comprehensive_scan_keeps_jobs_and_gets_our_report():
    scanner = DASTScanner(container_mode=True)
    plan = _write_user_plan(scanner, _CTFLEARN_PLAN)
    assert "authentication" not in plan["env"]["contexts"][0]
    job_types = [j["type"] for j in plan["jobs"]]
    assert job_types == ["passiveScan-config", "spider", "spiderAjax", "passiveScan-wait", "report"]
    report = [j for j in plan["jobs"] if j["type"] == "report"][0]["parameters"]
    assert report["template"] == "traditional-json"
    assert report["reportFile"] == "results"


def test_user_plan_existing_report_job_is_replaced_not_duplicated():
    scanner = DASTScanner(container_mode=True)
    plan_yaml = _CTFLEARN_PLAN + "- type: report\n  parameters:\n    template: traditional-html\n"
    plan = _write_user_plan(scanner, plan_yaml)
    report_jobs = [j for j in plan["jobs"] if j["type"] == "report"]
    assert len(report_jobs) == 1
    assert report_jobs[0]["parameters"]["template"] == "traditional-json"


def test_user_plan_rejects_non_plan_yaml():
    scanner = DASTScanner(container_mode=True)
    try:
        _write_user_plan(scanner, "foo: bar\n")
        assert False, "expected ValueError for a yaml file with no 'jobs' key"
    except ValueError:
        pass


def test_zap_plan_and_auth_flags_are_mutually_exclusive():
    scanner = DASTScanner(
        container_mode=True, plan_file="zap.yaml",
        auth_url="https://example.com/login", auth_username="u", auth_password="p",
    )
    try:
        scanner._check_automation_supported(is_baseline_or_full=False)
        assert False, "expected ValueError when both --zap-plan and --auth-* are given"
    except ValueError:
        pass


def test_validate_dast_scan_requires_command_or_plan():
    validator = ConfigValidator(scantype="DAST", softfail=False, skip_upload=True)
    validator.validate_dast_scan("", "HIGH", True, zap_plan="zap.yaml")
    try:
        validator.validate_dast_scan("", "HIGH", True)
        assert False, "expected ValueError when neither --command nor --zap-plan is given"
    except ValueError:
        pass


def test_validate_dast_scan_all_or_nothing():
    validator = ConfigValidator(scantype="DAST", softfail=False, skip_upload=True)
    validator.validate_dast_scan("zap-baseline.py -t https://x", "HIGH", True)
    validator.validate_dast_scan(
        "zap-baseline.py -t https://x", "HIGH", True,
        auth_url="https://x/login", auth_username="u", auth_password="p",
    )
    try:
        validator.validate_dast_scan("zap-baseline.py -t https://x", "HIGH", True, auth_username="u")
        assert False, "expected ValueError for partial auth args"
    except ValueError:
        pass


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok - {name}")
    print("All DAST auth checks passed.")
