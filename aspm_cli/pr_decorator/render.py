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

# Gate thresholds: max findings allowed per severity before the gate fails.
# None = unlimited. UNKNOWN defaults to unlimited - nothing to gate on
# without a real severity (see adapters.load_findings_checkov).
DEFAULT_THRESHOLDS = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": None, "LOW": None, "UNKNOWN": None}

FINDING_MARKER_RE = re.compile(r"accuknox-pr-decorator:finding:(\S+?) -->")

FOOTER = ("\n---\n"
          "\U0001F537 **[AccuKnox ASPM](https://accuknox.com)** — AI-powered, security-first PR review "
          "· [Docs](https://help.accuknox.com) · [Report an issue](https://github.com/accuknox)")

# GitHub caps an issue/PR comment body at 65536 chars. The summary no longer
# itemizes findings (they are inline comments), so hitting this needs a very
# verbose AI narrative - this is the final backstop so an oversized comment
# degrades to a truncation notice instead of a failed post.
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
    lines.append("Every finding is also commented inline on its line in the **Files changed** tab, "
                 "with the suggested fix where one exists.")
    lines.append("")
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
