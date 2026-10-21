"""
Self-check for the PR decorator's gate/severity/dedup/adapter logic.
Plain asserts, no framework: `python tests/test_pr_decorator.py`.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aspm_cli.pr_decorator.adapters import (  # noqa: E402
    detect_loader, load_all_findings, load_findings_checkov, load_findings_gitleaks_sarif,
    load_findings_secret, load_findings_trivy, load_findings_trufflehog_jsonl,
)
from aspm_cli.pr_decorator.pr_summary import (  # noqa: E402
    _build_narrative_prompt, _extract_symbols, _ground_severity, generate_pr_narrative, render_extra_sections, render_file_changes_table,
    render_flow_diagram, render_narrative,
)
from aspm_cli.pr_decorator.remediation import enrich_with_remediation  # noqa: E402
from aspm_cli.pr_decorator.render import (  # noqa: E402
    FINDING_MARKER_RE, compute_event, gate_status, load_findings,
    render_inline_comment, render_summary_comment,
)


def f(severity, path="a.py", line=1, fp="fp1", cwe=None):
    return {"path": path, "start_line": line, "end_line": line, "severity": severity, "rule_id": "x.rule",
            "cwe": cwe or [], "fingerprint": fp, "source": "AccuKnox SAST", "message": "m",
            "code": "", "fix": None, "owasp": None, "references": [], "category": "sast"}


def test_gate_status():
    assert gate_status({"HIGH": 0}, {"HIGH": 0, "MEDIUM": None, "LOW": None}) == []
    failed = gate_status({"HIGH": 2, "MEDIUM": 3}, {"HIGH": 0, "MEDIUM": None, "LOW": None})
    assert failed == [("HIGH", 2, 0)], failed
    failed = gate_status({"MEDIUM": 11}, {"HIGH": 0, "MEDIUM": 10, "LOW": None})
    assert failed == [("MEDIUM", 11, 10)], failed


def test_summary_no_findings():
    body = render_summary_comment([], {"repo": "o/r", "ref": "main", "sha": "abc"})
    assert "No issues found" in body
    assert "accuknox-pr-decorator:summary" in body


def test_summary_blocking_vs_advisory():
    findings = [f("HIGH")]
    meta = {"repo": "o/r", "ref": "main", "sha": "abc", "mode": "advisory"}
    assert "CRITICAL - Immediate" not in render_summary_comment(findings, meta)
    meta["mode"] = "blocking"
    assert "CRITICAL - Immediate" in render_summary_comment(findings, meta)


def test_compute_event():
    assert compute_event([f("HIGH")], "advisory") == "COMMENT"
    assert compute_event([f("HIGH")], "blocking") == "REQUEST_CHANGES"
    assert compute_event([f("LOW")], "blocking") == "COMMENT"


def test_finding_marker_roundtrip():
    body = render_inline_comment(f("HIGH", fp="abc-123"))
    m = FINDING_MARKER_RE.search(body)
    assert m and m.group(1) == "abc-123", body[:80]


def _write_json(data):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
        return fh.name


def test_load_findings_cwe_string_normalized_to_list():
    fixture = {"results": [
        {"check_id": "x.rule", "path": "a.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "m", "severity": "ERROR", "fingerprint": "fp",
                    "metadata": {"impact": "HIGH", "cwe": "CWE-319: Cleartext Transmission"}}},
    ]}
    path = _write_json(fixture)
    try:
        findings, _ = load_findings(path)
        assert findings[0]["cwe"] == ["CWE-319: Cleartext Transmission"], findings[0]["cwe"]
        section = render_inline_comment(findings[0])
        assert "C; W; E" not in section  # a bare string used to get joined character-by-character
    finally:
        os.unlink(path)


def test_load_findings_severity_from_impact_not_native_severity():
    # extra.metadata.impact (LOW/MEDIUM/HIGH/CRITICAL) is the real severity
    # signal - see scan/sast.py's own gate and the CSPM backend's Semgrep
    # parser. extra.severity (ERROR/WARNING/INFO) is a different axis and
    # must NOT be used to derive it, even though ERROR looks HIGH-ish.
    fixture = {"results": [
        {"check_id": "has.impact", "path": "a.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "m", "severity": "INFO", "fingerprint": "fp1",
                    "metadata": {"impact": "MEDIUM"}}},
        {"check_id": "no.impact", "path": "a.py", "start": {"line": 2}, "end": {"line": 2},
         "extra": {"message": "m", "severity": "ERROR", "fingerprint": "fp2",
                    "metadata": {}}},
    ]}
    path = _write_json(fixture)
    try:
        findings, _ = load_findings(path)
        has_impact = next(f for f in findings if f["rule_id"] == "has.impact")
        no_impact = next(f for f in findings if f["rule_id"] == "no.impact")
        assert has_impact["severity"] == "MEDIUM", has_impact["severity"]
        # impact absent -> UNKNOWN, never guessed from severity=ERROR
        assert no_impact["severity"] == "UNKNOWN", no_impact["severity"]
        assert no_impact["native_severity"] == "ERROR"  # raw value still preserved, just not used for the tier
    finally:
        os.unlink(path)


def test_checkov_line_zero_clamped_to_one():
    fixture = [{"check_type": "github_actions", "results": {"failed_checks": [
        {"check_id": "CKV2_GHA_1", "check_name": "whole-file check",
         "file_path": "/.github/workflows/x.yaml", "file_line_range": [0, 1], "severity": None},
    ]}}]
    path = _write_json(fixture)
    try:
        findings, _ = load_findings_checkov(path)
        # GitHub's review API rejects line 0 - must never post that
        assert findings[0]["start_line"] >= 1, findings[0]["start_line"]
    finally:
        os.unlink(path)


def test_detect_loader_routes_by_filename():
    assert detect_loader("foo-IAC-123.json") is load_findings_checkov
    assert detect_loader("foo-SG-123.json") is load_findings
    assert detect_loader("collector-TR-123.json") is load_findings_trivy
    assert detect_loader("foo-SCA-123.json") is load_findings_trivy
    assert detect_loader("results.json") is load_findings  # default


def test_trivy_adapter_uses_native_severity_and_anchors_line_1():
    fixture = {"ArtifactName": "org/repo", "Results": [
        {"Target": "app/composer.lock", "Type": "composer", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "Severity": "CRITICAL", "PkgName": "foo",
             "InstalledVersion": "1.0", "CweIDs": ["CWE-1"], "Title": "bad thing"},
            {"VulnerabilityID": "CVE-2", "Severity": "made-up-severity", "PkgName": "bar"},
        ]},
    ]}
    path = _write_json(fixture)
    try:
        findings, meta = load_findings_trivy(path)
        assert len(findings) == 2
        crit = next(f for f in findings if f["rule_id"] == "CVE-1")
        assert crit["severity"] == "CRITICAL"
        assert crit["start_line"] == 1  # dependency finding, no real line
        unknown = next(f for f in findings if f["rule_id"] == "CVE-2")
        assert unknown["severity"] == "UNKNOWN"  # unrecognized value doesn't crash or misclassify
        assert meta["repo"] == "org/repo"
    finally:
        os.unlink(path)


def test_checkov_adapter_is_severity_unknown():
    fixture = [
        {"check_type": "terraform", "results": {"failed_checks": [
            {"check_id": "CKV_AWS_1", "check_name": "Example check",
             "file_path": "/iac/main.tf", "file_line_range": [3, 5],
             "severity": None, "guideline": "https://example.com/CKV_AWS_1"},
        ]}},
        {"details": {"repo": "https://github.com/o/r.git"}},
    ]
    path = _write_json(fixture)
    try:
        findings, meta = load_findings_checkov(path)
        assert len(findings) == 1
        finding = findings[0]
        assert finding["severity"] == "UNKNOWN"
        assert finding["path"] == "iac/main.tf"  # leading "/" stripped
        assert "Guideline:" in finding["message"]
        assert meta["repo"] == "https://github.com/o/r.git"
    finally:
        os.unlink(path)


def test_checkov_code_block_is_line_pairs_not_a_string():
    # Confirmed against a real scan output sample: code_block is
    # [[line_no, "text\n"], ...], not a plain string. render_inline_comment
    # used to crash here with AttributeError: 'list' object has no
    # attribute 'strip'.
    fixture = [{"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_3", "file_path": "/main.tf", "file_line_range": [3, 7],
         "severity": None,
         "code_block": [[3, 'resource "aws_ebs_volume" "x" {\n'], [4, '  encrypted = false\n'],
                         [5, '}\n']]},
    ]}}]
    path = _write_json(fixture)
    try:
        findings, _ = load_findings_checkov(path)
        assert findings[0]["code"] == 'resource "aws_ebs_volume" "x" {\n  encrypted = false\n}\n'
        render_inline_comment(findings[0])  # must not raise
    finally:
        os.unlink(path)


def test_load_all_findings_scan_type_overrides_filename_sniffing():
    # scan/iac.py writes IaC's own Checkov shape to results_json.json - a
    # filename detect_loader() would otherwise (wrongly) sniff as SAST.
    fixture = [{"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_1", "file_path": "/main.tf", "file_line_range": [1, 1], "severity": None},
    ]}}]
    path = _write_json(fixture)
    try:
        findings, _ = load_all_findings([path], scan_types=["iac"])
        assert len(findings) == 1
        assert findings[0]["source"] == "AccuKnox IaC (Checkov)"
    finally:
        os.unlink(path)


def _write_jsonl(lines):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        for obj in lines:
            fh.write(json.dumps(obj) + "\n")
        return fh.name


def test_trufflehog_verified_vs_unverified_severity():
    fixture = [
        {"SourceMetadata": {"Data": {"Filesystem": {"file": "a.env", "line": 3}}},
         "DetectorName": "AWS", "Verified": True, "Raw": "AKIA-SUPER-SECRET-RAW-VALUE",
         "Redacted": "AKIA****VALUE"},
        {"SourceMetadata": {"Data": {"Filesystem": {"file": "b.env", "line": 9}}},
         "DetectorName": "Generic", "Verified": False, "Raw": "totally-secret-raw",
         "Redacted": "tota****raw"},
    ]
    path = _write_jsonl(fixture)
    try:
        findings, _ = load_findings_trufflehog_jsonl(path)
        assert len(findings) == 2
        verified = next(f for f in findings if f["path"] == "a.env")
        unverified = next(f for f in findings if f["path"] == "b.env")
        assert verified["severity"] == "CRITICAL", verified["severity"]
        assert unverified["severity"] == "HIGH", unverified["severity"]
        # never render the raw secret value - only the pre-masked Redacted one
        assert verified["code"] == "" and unverified["code"] == ""
        for f in findings:
            body = render_inline_comment(f)
            assert "SUPER-SECRET-RAW-VALUE" not in body
            assert "totally-secret-raw" not in body
        assert "AKIA****VALUE" in render_inline_comment(verified)
    finally:
        os.unlink(path)


def test_trufflehog_git_source_type_not_just_filesystem():
    # docs/onprem-setup-guide.md documents the real command as
    # `secret --command "git file://." --container-mode`, which puts file/
    # line under SourceMetadata.Data.Git, not .Filesystem.
    fixture = [{"SourceMetadata": {"Data": {"Git": {
        "repository": "https://github.com/o/r.git", "commit": "abc123",
        "file": "app.py", "line": 7, "email": "dev@example.com"}}},
        "DetectorName": "AWS", "Verified": True, "Redacted": "AKIA****"}]
    path = _write_jsonl(fixture)
    try:
        findings, _ = load_findings_trufflehog_jsonl(path)
        assert len(findings) == 1
        assert findings[0]["path"] == "app.py"
        assert findings[0]["start_line"] == 7
    finally:
        os.unlink(path)


def test_trufflehog_skips_blank_and_malformed_lines():
    path = _write_jsonl([{"SourceMetadata": {"Data": {"Filesystem": {"file": "a.py", "line": 1}}},
                           "DetectorName": "X", "Verified": False}])
    try:
        with open(path, "a") as fh:
            fh.write("\nnot-json\n")
        findings, _ = load_findings_trufflehog_jsonl(path)
        assert len(findings) == 1
    finally:
        os.unlink(path)


def test_gitleaks_sarif_findings_and_line_clamp():
    fixture = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "gitleaks"}},
        "results": [
            {"ruleId": "aws-access-token", "message": {"text": "aws-access-token detected"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "config.yml"},
                 "region": {"startLine": 0, "endLine": 0}}}]},
        ],
    }]}
    path = _write_json(fixture)
    try:
        findings, _ = load_findings_gitleaks_sarif(path)
        assert len(findings) == 1
        f = findings[0]
        assert f["path"] == "config.yml"
        assert f["start_line"] >= 1  # SARIF region can be 0; GitHub's API rejects that
        assert f["severity"] == "HIGH"
        assert f["code"] == ""  # never render the matched snippet
    finally:
        os.unlink(path)


def test_remediation_skipped_without_api_key_no_network_call():
    fixture = {"results": [
        {"check_id": "x.rule", "path": "a.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "m", "lines": "code"}},
    ]}
    path = _write_json(fixture)
    try:
        generated = enrich_with_remediation(path, api_key=None)  # no key -> must not attempt a call
        assert generated == 0
        with open(path) as f:
            data = json.load(f)
        assert "remediation" not in data["results"][0]["extra"]  # file left untouched
    finally:
        os.unlink(path)


def test_load_findings_secret_dispatches_by_extension():
    jsonl_path = _write_jsonl([{"SourceMetadata": {"Data": {"Filesystem": {"file": "a", "line": 1}}},
                                 "DetectorName": "X", "Verified": True}])
    sarif_path = _write_json({"runs": [{"results": [
        {"ruleId": "r", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "b"}, "region": {"startLine": 1}}}]},
    ]}]})
    try:
        jsonl_findings, _ = load_findings_secret(jsonl_path)
        sarif_findings, _ = load_findings_secret(sarif_path)
        assert jsonl_findings[0]["source"] == "AccuKnox Secrets (TruffleHog)"
        assert sarif_findings[0]["source"] == "AccuKnox Secrets (Gitleaks)"
    finally:
        os.unlink(jsonl_path)
        os.unlink(sarif_path)


def test_unknown_severity_never_itemized_in_summary():
    # Checkov OSS never sets real severity - every IaC finding lands here.
    # A wall of unrated findings is noise, not signal (see DISPLAYED_SEVERITIES).
    findings = [f("UNKNOWN", fp=f"fp{i}") for i in range(5)]
    body = render_summary_comment(findings, {"repo": "o/r", "ref": "main", "sha": "abc"})
    assert "No rated issues found" in body
    assert "5 additional finding" in body
    assert "UNKNOWN Issues" not in body  # never an itemized section for it


def test_unknown_mixed_with_rated_findings_still_excluded():
    findings = [f("HIGH"), f("UNKNOWN", fp="fp2")]
    body = render_summary_comment(findings, {"repo": "o/r", "ref": "main", "sha": "abc"})
    assert "Found **1 finding(s)**" in body  # headline excludes the UNKNOWN one
    assert "additional finding" not in body  # unrated noise is not mentioned at all
    assert "UNKNOWN Issues" not in body


def test_summary_comment_never_exceeds_hard_size_cap():
    # Many files, many severities, long messages - well beyond what real
    # per-finding/per-severity caps alone are tuned for.
    findings = []
    for i in range(200):
        sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4]
        ff = f(sev, path=f"file{i}.py", line=i + 1, fp=f"fp{i}")
        ff["message"] = "a very long finding message. " * 50
        findings.append(ff)
    body = render_summary_comment(findings, {"repo": "o/r", "ref": "main", "sha": "abc"})
    assert len(body) <= 60000


def test_extract_symbols_python_and_terraform():
    diff = (
        "+def handle_request(req):\n"
        "+    pass\n"
        '+resource "aws_s3_bucket" "logs" {\n'
        "-def old_unused(x):\n"  # removed line must not contribute
    )
    symbols = _extract_symbols(diff)
    assert symbols == ["handle_request", "logs"]


def test_render_file_changes_table_caps_and_notes_remainder():
    rows = [{"path": f"f{i}.py", "added": "1", "deleted": "0", "symbols": []} for i in range(15)]
    table = render_file_changes_table(rows)
    assert table.count("| `f") == 10  # _MAX_FILES_IN_TABLE
    assert "and 5 more file(s)" in table


def test_generate_pr_narrative_skipped_without_key_or_diff():
    assert generate_pr_narrative([{"path": "a"}], [], api_key=None) is None
    assert generate_pr_narrative(None, [], api_key="key") is None


def test_render_flow_diagram_empty_without_findings():
    assert render_flow_diagram([]) == ""
    diagram = render_flow_diagram([f("HIGH", path="a.py")])
    assert "```mermaid" in diagram
    assert "a.py" in diagram
    assert "classDef" not in diagram and "linkStyle" not in diagram  # no coloured boxes
    assert "PR --> F0" in diagram


def test_render_flow_diagram_rows_per_line_marked_by_severity():
    findings = [f("CRITICAL", path="r.txt", line=1, fp="1"), f("HIGH", path="r.txt", line=1, fp="2"),
                f("LOW", path="r.txt", line=1, fp="3"), f("MEDIUM", path="a.py", line=9, fp="4"),
                f("HIGH", path="a.py", line=3, fp="5"), f("UNKNOWN", path="u.py", fp="6")]
    d = render_flow_diagram(findings)
    assert '🔴 L1 · rule +2' in d               # 3 findings on one line -> one row
    assert d.index("r.txt") < d.index("a.py")   # worst file first
    assert "u.py" not in d                      # UNKNOWN is never shown
    assert "L3" in d and "L9" in d
    assert "🔴 1 · 🟠 1 · ⚪ 1" in d             # per-file severity counts on the file box


def test_summary_does_not_repeat_inline_findings():
    body = render_summary_comment([f("HIGH", line=7)], {"repo": "o/r", "ref": "main", "sha": "abc"})
    assert "HIGH Issues" not in body and "a.py:7" not in body


def test_summary_has_no_boilerplate_notes():
    body = render_summary_comment([f("HIGH"), f("UNKNOWN", fp="2")], {"repo": "o/r", "mode": "advisory"})
    assert "advisory mode" not in body and "commented inline" not in body


def test_render_narrative_impact_cards_and_string_fallback():
    n = {"summary": "Adds billing.", "what_it_does": ["Adds lookup()"],
         "impact": [{"severity": "high", "where": "a.py:12", "title": "SQL injection in lookup",
                     "risk": "Caller can dump the | billing DB.", "action": "Parametrize the query", "effort": "low"}]}
    out = render_narrative(n)
    assert "- 🟠 **HIGH** · `a.py:12` — **SQL injection in lookup** ⚡" in out
    assert "  - **Why it matters:** Caller can dump the / billing DB." in out  # pipe neutralised
    assert "  - **Fix:** Parametrize the query _(effort: low)_" in out
    assert "_Adds billing._" in out and "- Adds lookup()" in out
    legacy = render_narrative({"what_it_does": ["x"], "impact": ["plain bullet"]})
    assert "- plain bullet" in legacy and "Why it matters" not in legacy


def test_rejected_inline_comments_are_retried_one_by_one():
    from types import SimpleNamespace
    from aspm_cli.pr_decorator.providers import github as gh
    calls = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url.rsplit("/", 1)[-1], json))
        if url.endswith("/reviews") and json["comments"]:
            return SimpleNamespace(status_code=422, text="Line could not be resolved")
        if url.endswith("/comments") and json["path"] == "bad.py":
            return SimpleNamespace(status_code=422, text="nope")
        return SimpleNamespace(status_code=200, text="", raise_for_status=lambda: None)

    real = gh.requests.post
    gh.requests.post = fake_post
    try:
        gh.GitHubProvider("o/r", "1", "sha", "tok").post_review(
            "body", "COMMENT",
            [{"path": "good.py", "line": 3, "body": "x"}, {"path": "bad.py", "line": 9, "body": "y"}], False)
    finally:
        gh.requests.post = real
    kinds = [c[0] for c in calls]
    assert kinds == ["reviews", "reviews", "comments", "comments"], kinds
    assert calls[1][1]["comments"] == []           # body-only review still posted
    assert calls[2][1]["path"] == "good.py"         # the resolvable comment is not lost


def test_impact_severity_comes_from_the_scanner_not_the_model():
    fs = [f("HIGH", path="s.py", line=2), f("LOW", path="s.py", line=9, fp="2")]
    rows = _ground_severity([{"severity": "MEDIUM", "where": "s.py:2-4"},
                             {"severity": "LOW", "where": "s.py"},
                             {"severity": "LOW", "where": "other.py:1"}], fs)
    assert [r["severity"] for r in rows] == ["HIGH", "HIGH", "LOW"]  # unmatched row keeps the model's


def test_render_narrative_sorts_impact_worst_first():
    mk = lambda sev, w: {"severity": sev, "where": w, "title": w, "risk": "r", "action": "a"}
    out = render_narrative({"impact": [mk("LOW", "l.py"), mk("CRITICAL", "c.py"), mk("MEDIUM", "m.py"), mk("HIGH", "h.py")]})
    assert [out.index(x) for x in ("c.py", "h.py", "m.py", "l.py")] == sorted(out.index(x) for x in ("c.py", "h.py", "m.py", "l.py"))


def test_narrative_prompt_shows_changed_lines_but_never_for_secret_files():
    rows = [{"path": "app.py", "added": "2", "deleted": "0", "symbols": ["run"], "excerpt": ["def run(): pass"]},
            {"path": "settings.py", "added": "1", "deleted": "0", "symbols": [], "excerpt": ["KEY = 'AKIA...'"]}]
    secret = dict(f("HIGH", path="settings.py"), category="secret")
    prompt = _build_narrative_prompt(rows, [secret])
    assert "+ def run(): pass" in prompt
    assert "AKIA" not in prompt and "changed lines not shown" in prompt


def test_quality_finding_title_comes_from_the_comment(tmp=None):
    path = _write_json({"comments": [{"path": "a.py", "start_line": 5, "end_line": 5, "category": "other",
                                      "severity": "high", "content": "File handle is never closed. Use a with block."}]})
    try:
        findings, _ = load_all_findings([path], None, ["quality"])
        assert findings[0]["rule_id"] == "File handle is never closed", findings[0]["rule_id"]
        assert findings[0]["severity"] == "MEDIUM"
    finally:
        os.unlink(path)


def test_render_extra_sections_all_empty_produces_empty_string():
    assert render_extra_sections(None, None, []) == ""


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print(f"{len(tests)} passed")
