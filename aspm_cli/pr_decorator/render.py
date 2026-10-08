"""
PR Decorator - comment renderer.

Turns normalized findings (see adapters.py) into GitHub-ready markdown: a PR
summary comment (severity table + quality gate) and per-finding inline
comment bodies. Provider-agnostic - started as a port of the standalone
PR-Decorator action (accuknox/PR-Decorator), since corrected against this
CLI's own real scan output and the CSPM backend's parsers (source of truth
for which raw fields matter) where they diverged from the original port.
"""
import json
import re
from collections import Counter

SEVERITY_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1", "LOW": "⚪", "UNKNOWN": "❔"}
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

# UNKNOWN (Checkov OSS never sets a real severity - every IaC finding lands
# here, see adapters.load_findings_checkov) is deliberately never itemized
# in the PR comment: dozens of unrated findings from one resource block is
# noise, not signal. Still counted internally (gate/dedup), just not shown.
DISPLAYED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Cap on fully-detailed <details> blocks per severity tier in the summary -
# GitHub caps a comment body at 65536 chars; a large scan (we've seen 5000+
# IaC findings on one real repo) would blow past that if every finding got
# a full collapsible block. The rest fall back to a one-line index entry.
# (There's also a hard _MAX_COMMENT_CHARS backstop below regardless of this.)
MAX_DETAILED_PER_SEVERITY = 10

# Gate thresholds: max findings allowed per severity before the gate fails.
# None = unlimited. UNKNOWN defaults to unlimited - nothing to gate on
# without a real severity (see adapters.load_findings_checkov).
DEFAULT_THRESHOLDS = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": None, "LOW": None, "UNKNOWN": None}

FINDING_MARKER_RE = re.compile(r"accuknox-pr-decorator:finding:(\S+?) -->")

FOOTER = ("\n---\n"
          "\U0001F537 **[AccuKnox ASPM](https://accuknox.com)** — AI-powered, security-first PR review "
          "· [Docs](https://help.accuknox.com) · [Report an issue](https://github.com/accuknox)")

# GitHub caps an issue/PR comment body at 65536 chars. The per-finding caps
# above (MAX_DETAILED_PER_SEVERITY, _MAX_CONTEXT_LINES) make hitting this
# unlikely, not impossible (many severities x many files x a verbose AI
# narrative) - this is the final backstop so an oversized comment degrades
# to a truncation notice instead of a failed post.
_MAX_COMMENT_CHARS = 60000


def _finalize(lines):
    body = "\n".join(lines) + FOOTER
    if len(body) > _MAX_COMMENT_CHARS:
        cutoff = _MAX_COMMENT_CHARS - len(FOOTER) - 250
        body = (body[:cutoff] + "\n\n... _(truncated - this PR has more content than fits in one "
                 "comment; see the inline review comments for the full finding set)_\n" + FOOTER)
    return body


def load_findings(path, changed_files=None):
    """OpenGrep/SAST result loader - the default shape adapters.py falls
    back to for any file it can't otherwise identify."""
    with open(path) as f:
        data = json.load(f)

    findings = []
    for r in data["results"]:
        if changed_files is not None and r["path"] not in changed_files:
            continue  # diff-scope filter
        extra = r["extra"]
        metadata = extra.get("metadata", {})
        native_sev = extra.get("severity", "INFO")
        # Severity tier comes from extra.metadata.impact (LOW/MEDIUM/HIGH/
        # CRITICAL) - the same signal scan/sast.py's own quality gate uses
        # ("OpenGrep already rates each finding on the standard scale via
        # extra.metadata.impact... The rule-level extra.severity (ERROR/
        # WARNING/INFO) is a different axis"), and what the CSPM backend's
        # own Semgrep parser reads for risk_factor. Confirmed against a real
        # scan sample: impact is absent on ~85% of default-ruleset findings
        # (most rules don't carry one) - those fall to UNKNOWN, same policy
        # as Checkov's null severity, rather than invented from extra.severity.
        impact = (metadata.get("impact") or "").upper()
        severity = impact if impact in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN"
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, str):  # some rules report a single CWE as a bare string
            cwe = [cwe]
        findings.append({
            "rule_id": r["check_id"],
            "path": r["path"],
            "start_line": r["start"]["line"],
            "end_line": r["end"]["line"],
            "message": extra.get("message", ""),
            "severity": severity,
            "native_severity": native_sev,
            "cwe": cwe,
            "owasp": metadata.get("owasp"),
            "confidence": metadata.get("confidence"),
            "category": metadata.get("category"),
            "code": extra.get("lines", ""),
            "fingerprint": extra.get("fingerprint", ""),
            "fix": r.get("fix") or extra.get("fix") or extra.get("remediation"),
            "references": metadata.get("references") or [],
            "source": metadata.get("source", "AccuKnox SAST"),
        })
    meta = {
        "repo": data.get("repo"),
        "sha": data.get("sha"),
        "ref": data.get("ref"),
        "repo_url": data.get("repo_url"),
        "ai_analysis": data.get("ai_analysis", False),
    }
    return findings, meta


def gate_status(counts, thresholds):
    """Which severities exceeded their configured threshold. Empty = passed."""
    failed = []
    for sev in SEVERITY_ORDER:
        limit = thresholds.get(sev)
        found = counts.get(sev, 0)
        if limit is not None and found > limit:
            failed.append((sev, found, limit))
    return failed


def compute_event(findings, mode):
    """GitHub review event: REQUEST_CHANGES only in blocking mode with a
    CRITICAL/HIGH finding present, COMMENT otherwise."""
    blocking_severities = ("CRITICAL", "HIGH")
    has_blocker = any(f["severity"] in blocking_severities for f in findings)
    return "REQUEST_CHANGES" if (mode == "blocking" and has_blocker) else "COMMENT"


_MAX_CONTEXT_LINES = 25  # hard cap - a Checkov check can span a huge resource
                          # block; without this, one finding could balloon the
                          # comment past GitHub's 65536-char limit on its own.


def _read_code_context(path, start_line, end_line, context=2):
    """Lines start_line-context..end_line+context read straight from the
    checked-out file (decorate-pr always runs inside the PR's checkout), the
    target range marked with an arrow - richer than a tool-provided
    single-line snippet. None on any read failure (deleted/renamed/unreadable
    file) - callers fall back to the finding's own `code` field."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    if not lines:
        return None
    lo = max(start_line - context, 1)
    hi = min(end_line + context, len(lines))
    truncated = False
    if hi - lo + 1 > _MAX_CONTEXT_LINES:
        hi = lo + _MAX_CONTEXT_LINES - 1
        truncated = True
    out = []
    for n in range(lo, hi + 1):
        marker = "⚠️ " if start_line <= n <= end_line else "   "
        out.append(f"{marker}{n}: {lines[n - 1].rstrip(chr(10))}")
    if truncated:
        out.append(f"   ... ({end_line - hi} more line(s) truncated)")
    return "\n".join(out)


def render_finding_detail(f, index):
    """Rich collapsible block for one finding: full description, CWE/OWASP,
    code with surrounding context, suggested fix, references. Used for the
    summary comment's top findings per tier (see MAX_DETAILED_PER_SEVERITY);
    render_inline_comment covers every finding on its own PR review thread."""
    rule_short = f["rule_id"].split(".")[-1]
    lines = ["<details>",
              f"<summary><b>{index}. {f['severity']} in {f['path']}:{f['start_line']}</b> "
              f"- <code>{rule_short}</code></summary>", ""]

    line_range = str(f["start_line"]) if f["start_line"] == f["end_line"] else f"{f['start_line']}-{f['end_line']}"
    lines += ["| | |", "|---|---|",
              f"| **File** | `{f['path']}` |",
              f"| **Lines** | {line_range} |",
              f"| **Severity** | {SEVERITY_ICON[f['severity']]} {f['severity']} |",
              f"| **Rule** | `{f['rule_id']}` |"]
    if f["cwe"]:
        lines.append(f"| **CWE** | {'; '.join(f['cwe'])} |")
    owasp = f.get("owasp")
    if owasp:
        owasp_list = owasp if isinstance(owasp, list) else [owasp]
        lines.append(f"| **OWASP** | {'; '.join(owasp_list)} |")
    lines += ["", "**Description:**", "", f["message"], ""]

    # Never re-read secret findings from disk - their own `code` is already
    # deliberately empty to avoid re-leaking the matched value (see
    # adapters.load_findings_trufflehog_jsonl / load_findings_gitleaks_sarif).
    code = None
    if f.get("category") != "secret" and f.get("path"):
        code = _read_code_context(f["path"], f["start_line"], f["end_line"])
    if code is None:
        code = f.get("code", "")
    if code:
        lines += ["**Code:**", "```", code.strip(), "```", ""]

    if f.get("fix"):
        lines += ["**Suggested Fix:**", "```suggestion", f["fix"], "```", ""]

    if f.get("references"):
        lines.append("**References:**")
        for ref in f["references"]:
            lines.append(f"- {ref}")
        lines.append("")

    lines.append("</details>")
    return "\n".join(lines)


def render_severity_section(findings, severity):
    """Rich collapsible detail for the first MAX_DETAILED_PER_SEVERITY
    findings in this tier, a compact index line for the rest (GitHub caps a
    comment body at 65536 chars - a large scan would blow past that if every
    finding got a full block; see MAX_DETAILED_PER_SEVERITY)."""
    items = sorted((f for f in findings if f["severity"] == severity),
                    key=lambda x: (x["path"], x["start_line"]))
    if not items:
        return ""
    lines = [f"### {SEVERITY_ICON[severity]} {severity} Issues ({len(items)} found)", ""]
    detailed, rest = items[:MAX_DETAILED_PER_SEVERITY], items[MAX_DETAILED_PER_SEVERITY:]
    for i, f in enumerate(detailed, 1):
        lines.append(render_finding_detail(f, i))
        lines.append("")
    if rest:
        lines.append(f"<details><summary>+ {len(rest)} more {severity} finding(s)</summary>")
        lines.append("")
        for f in rest:
            cwe = f" — _{'; '.join(f['cwe'])}_" if f["cwe"] else ""
            lines.append(f"- `{f['path']}:{f['start_line']}` — `{f['rule_id'].split('.')[-1]}`{cwe}")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines)


def render_summary_comment(findings, meta, thresholds=None, extra_sections=None):
    thresholds = thresholds if thresholds is not None else DEFAULT_THRESHOLDS
    counts = Counter(f["severity"] for f in findings)
    # UNKNOWN is never itemized (see DISPLAYED_SEVERITIES) - the headline
    # count and "no issues" check are about what's actually shown, not
    # Checkov's unrated noise.
    total = sum(counts.get(sev, 0) for sev in DISPLAYED_SEVERITIES)
    unknown_total = counts.get("UNKNOWN", 0)
    failed = gate_status(counts, thresholds)
    mode = meta.get("mode", "advisory")
    blocking = bool(failed) and mode == "blocking"

    lines = ["<!-- accuknox-pr-decorator:summary -->", "# \U0001F6E1️ AccuKnox Security Review", ""]

    lines.append("## \U0001F4CA Pull Request Summary")
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| **Repository** | `{meta.get('repo') or 'unknown'}` |")
    if meta.get("pr_number"):
        lines.append(f"| **PR** | #{meta['pr_number']} |")
    if blocking:
        status = "\U0001F6A8 CRITICAL - Immediate Action Required"
    elif failed:
        status = "⚠️ Needs Review"
    else:
        status = "✅ Passed"
    lines.append(f"| **Security Status** | {status} |")
    lines.append("")
    lines.append(f"_Scanned `{meta.get('ref') or 'unknown ref'}` @ `{(meta.get('sha') or 'unknown sha')[:10]}` "
                  f"| AI analysis: {'on' if meta.get('ai_analysis') else 'off'}_")
    lines.append("")

    if total:
        lines.append("## \U0001F6A6 Quality Gate")
        lines.append("")
        if not failed:
            lines.append("✅ **Passed** — within configured thresholds.")
        else:
            lines.append("❌ **Failed**")
            lines.append("")
            lines.append("**Failed conditions**")
            for sev, found, limit in failed:
                lines.append(f"- {SEVERITY_ICON[sev]} {sev}: found {found}, threshold {limit}")
        lines.append("")

    if extra_sections:
        lines.append(extra_sections)

    if total == 0:
        if unknown_total:
            lines.append("## ✅ No rated issues found")
            lines.append("")
            lines.append(f"AccuKnox found no CRITICAL/HIGH/MEDIUM/LOW issues in changed code. "
                          f"({unknown_total} additional finding(s) with no severity signal from the "
                          f"scanner were also detected but aren't itemized here.)")
        else:
            lines.append("## ✅ No issues found")
            lines.append("")
            lines.append("AccuKnox reviewed your code and found no material issues that require review.")
        return _finalize(lines)

    lines.append("## \U0001F6E1️ Security Findings")
    lines.append("")
    lines.append(f"Found **{total} finding(s)** in changed code:")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in DISPLAYED_SEVERITIES:
        if counts.get(sev):
            lines.append(f"| {SEVERITY_ICON[sev]} {sev} | {counts[sev]} |")
    lines.append("")
    for sev in DISPLAYED_SEVERITIES:
        section = render_severity_section(findings, sev)
        if section:
            lines.append(section)
    if unknown_total:
        lines.append(f"_{unknown_total} additional finding(s) with no severity signal from the scanner "
                      f"(e.g. Checkov OSS reports none natively) - not itemized above._")
        lines.append("")

    lines.append("## ✅ Review Status")
    lines.append("")
    if blocking:
        lines.append("**Recommendation:** \U0001F6A8 **Changes requested** — thresholds exceeded.")
    elif failed:
        lines.append("**Recommendation:** ⚠️ Review recommended — thresholds exceeded "
                      "(advisory mode, not blocking).")
    else:
        lines.append("**Recommendation:** ✅ No blocking issues found.")
    return _finalize(lines)


def render_inline_comment(f):
    lines = []
    lines.append(f"<!-- accuknox-pr-decorator:finding:{f['fingerprint']} -->")
    lines.append(f"{SEVERITY_ICON[f['severity']]} **{f['severity']}** "
                  f"— {f['rule_id'].split('.')[-1].replace('-', ' ')}")
    lines.append(f"_Detected by {f['source']}_")
    lines.append("")
    lines.append(f["message"])
    if f["cwe"]:
        lines.append("")
        lines.append("**CWE:** " + "; ".join(f["cwe"]))
    if f["code"]:
        lines.append("")
        lines.append("```")
        lines.append(f["code"].strip())
        lines.append("```")
    lines.append("")
    if f.get("fix"):
        lines.append("**Suggested fix:**")
        lines.append("```suggestion")
        lines.append(f["fix"])
        lines.append("```")
    else:
        lines.append("_No automatic fix available for this rule — remediation needs to be "
                      "reviewed manually._")
    return "\n".join(lines)
