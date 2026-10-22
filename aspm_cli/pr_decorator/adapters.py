"""
Adapters that normalize each scan type's native result JSON into the common
finding-dict shape render.py renders - so render_summary_comment /
render_inline_comment don't change per scan type, only what feeds them does.

Loader selection is explicit by scan type (LOADERS_BY_SCANTYPE), matching
what `aspm-cli scan <type>` actually wrote (results.json for sast/sca,
results_json.json for iac - see scan/sast.py, scan/iac.py, scan/trivy_runner.py).
Falls back to filename sniffing (detect_loader) only when no scan type is
given, for callers working from AccuKnox-labeled files (<label>-<TYPE>-*.json)
instead of this CLI's own local scan output.

`secret` findings come from one of two engines (scan/secret.py): TruffleHog
(default, JSON-per-line to results.jsonl) or Gitleaks (results.json, SARIF).
load_findings_secret() picks the loader by extension, matching
SecretScanner.result_file's own .jsonl/.json split - no separate flag needed.

CAVEAT: unlike the checkov/trivy/sast loaders (each verified against this
CLI's own real output), the two secret loaders below are built against
TruffleHog v3's and SARIF 2.1.0's public documented schemas, not a live
sample - no docker/network access was available to generate one. Both specs
are stable and versioned, so this isn't a blind guess, but run once against
real findings before trusting it in production (same caveat generate_
remediation.py already carries for its own untested LLM call).
"""
import hashlib
import json
import os
import re
import textwrap

from .render import load_findings as load_findings_sast


def _fingerprint(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()


def _checkov_code_block_to_str(raw):
    """Checkov's code_block is [[line_no, "line text\\n"], ...], not a plain
    string - confirmed against a real scan output sample. Join it back into
    one block; defend against a bare string too in case that ever changes."""
    if isinstance(raw, list):
        return "".join(text for _, text in raw)
    return raw or ""


def load_findings_checkov(path, changed_files=None):
    """Checkov (IaC) JSON: a list of {check_type, results: {failed_checks:
    [...]}} blocks, plus a trailing {"details": {...}} metadata block with no
    "results" key (skipped) - see scan/iac.py's process_result_file.

    Checkov (OSS, no Bridgecrew/Prisma account) reports `"severity": null` on
    every built-in check - there is no severity signal to map. Rather than
    invent one, every finding here is severity UNKNOWN: still shown, still
    gets an inline PR comment, just excluded from the HIGH/MEDIUM/LOW gate by
    default (see DEFAULT_THRESHOLDS) so it's never silently bucketed as LOW."""
    with open(path) as f:
        data = json.load(f)

    findings = []
    for entry in data:
        results = entry.get("results")
        if not results:
            continue
        check_type = entry.get("check_type", "iac")
        for c in results.get("failed_checks", []):
            file_path = (c.get("file_path") or "").lstrip("/")
            if changed_files is not None and file_path not in changed_files:
                continue
            # File/resource-level checks report file_line_range starting at
            # 0 - GitHub's review API rejects line 0 (must be >= 1) and would
            # fail the *entire* review POST, not just this one comment.
            raw_range = c.get("file_line_range") or [1, 1]
            line_range = [max(raw_range[0], 1), max(raw_range[-1], 1)]
            message = c.get("check_name") or c.get("check_id") or ""
            if c.get("guideline"):
                message = f"{message}\n\nGuideline: {c['guideline']}"
            findings.append({
                "rule_id": c.get("check_id", ""),
                "path": file_path,
                "start_line": line_range[0],
                "end_line": line_range[-1],
                "message": message,
                "severity": "UNKNOWN",
                "native_severity": c.get("severity") or "UNKNOWN",
                "cwe": [],
                "owasp": None,
                "confidence": None,
                "category": check_type,
                "code": _checkov_code_block_to_str(c.get("code_block")),
                "fingerprint": _fingerprint("checkov", c.get("check_id"), file_path, line_range[0]),
                "fix": None,
                "references": [c["guideline"]] if c.get("guideline") else [],
                "source": "AccuKnox IaC",
            })

    repo = None
    for entry in data:
        if "details" in entry:
            repo = entry["details"].get("repo")
    meta = {"repo": repo, "sha": None, "ref": None, "ai_analysis": False}
    return findings, meta


def load_findings_trivy(path, changed_files=None):
    """Trivy (SCA) JSON: {"ArtifactName", "Results": [{"Target": <path>,
    "Vulnerabilities": [{"VulnerabilityID", "Severity", "PkgName", ...}]}]} -
    the native shape scan/trivy_runner.py writes as-is (`-f json -o ...`).

    Trivy reports a real severity per vulnerability already in the
    CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN vocabulary this codebase uses - no
    mapping needed, just defend against an unrecognized value.

    A vulnerability applies to a whole dependency file (e.g. composer.lock),
    not one line of it, so every finding anchors to line 1 rather than
    guessing a line GitHub might reject."""
    with open(path) as f:
        data = json.load(f)

    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        if changed_files is not None and target not in changed_files:
            continue
        for v in result.get("Vulnerabilities") or []:
            message = v.get("Title") or v.get("Description") or v.get("VulnerabilityID", "")
            details = []
            if v.get("PkgName"):
                details.append(f"**Package:** `{v['PkgName']}` {v.get('InstalledVersion', '')}".rstrip())
            if v.get("FixedVersion"):
                details.append(f"**Fixed in:** {v['FixedVersion']}")
            if v.get("PrimaryURL"):
                details.append(v["PrimaryURL"])
            if details:
                message = message + "\n\n" + "\n".join(details)
            severity = (v.get("Severity") or "UNKNOWN").upper()
            if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity = "UNKNOWN"
            findings.append({
                "rule_id": v.get("VulnerabilityID", ""),
                "path": target,
                "start_line": 1,
                "end_line": 1,
                "message": message,
                "severity": severity,
                "native_severity": v.get("Severity") or "UNKNOWN",
                "cwe": v.get("CweIDs") or [],
                "owasp": None,
                "confidence": None,
                "category": result.get("Type", "sca"),
                "code": "",
                "fingerprint": v.get("Fingerprint") or _fingerprint(
                    "trivy", v.get("VulnerabilityID"), target, v.get("PkgName")),
                "fix": None,
                "references": [v["PrimaryURL"]] if v.get("PrimaryURL") else [],
                "source": "AccuKnox SCA",
            })

    meta = {"repo": data.get("ArtifactName"), "sha": None, "ref": None, "ai_analysis": False}
    return findings, meta


def load_findings_trufflehog_jsonl(path, changed_files=None):
    """TruffleHog v3 `--json` output: one JSON object per line (docker
    stdout, see scan/secret.py's _run_trufflehog / write_stdout=True). Each
    line's documented shape (github.com/trufflesecurity/trufflehog):
        {"SourceMetadata": {"Data": {<SourceType>: {"file", "line", ...}}},
         "DetectorName", "Verified", "Raw", "Redacted", ...}

    <SourceType> depends on how trufflehog was invoked, not a fixed key -
    "Git" for the documented real command (docs/onprem-setup-guide.md:
    `secret --command "git file://." --container-mode`), "Filesystem" for a
    bare `filesystem .`, etc. Confirmed against the CSPM backend's own
    TruffleHogParser (source/parsers/trufflehog.py), which handles the same
    ambiguity by taking whichever single key is present under Data - exactly
    one is, since that's however this run was invoked. "file"/"line" exist
    under all of them (Git/Github/Gitlab/Huggingface/Filesystem all carry
    those two; S3/Gcs carry other path fields as a rarer case not scanned
    from a git repo, so not handled here).

    Severity is TruffleHog's own `Verified` flag, not a native tier - it has
    none. Verified=true means the credential was confirmed *live* against
    the provider's API (the most urgent class of finding this integration
    can produce) -> CRITICAL. Verified=false is a pattern match only (could
    be a false positive, a rotated/dead key, or real) -> HIGH, for manual
    triage. This policy (not a fact about TruffleHog) matches the CSPM
    backend parser's own risk_factor exactly: RISKS.HIGH, RISKS.CRITICAL if
    verified.

    Never renders `Raw` (the actual secret value) into a PR comment - only
    the already-masked `Redacted` field. `code` is left empty on purpose so
    render_inline_comment never prints a code block that could re-leak the
    secret in context."""
    findings = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue  # TruffleHog only writes JSON lines in --json mode; skip anything stray

            source_data = (r.get("SourceMetadata") or {}).get("Data") or {}
            fs = next(iter(source_data.values()), {})  # exactly one source-type key is present
            file_path = fs.get("file", "")
            if changed_files is not None and file_path not in changed_files:
                continue
            line_no = fs.get("line") or 1
            verified = bool(r.get("Verified"))
            detector = r.get("DetectorName", "secret")
            redacted = r.get("Redacted", "")

            findings.append({
                "rule_id": detector,
                "path": file_path,
                "start_line": line_no,
                "end_line": line_no,
                "message": (f"Verified live credential detected ({detector})." if verified
                            else f"Possible secret detected ({detector}) - unverified, review before dismissing.")
                           + (f"\n\n**Masked value:** `{redacted}`" if redacted else ""),
                "severity": "CRITICAL" if verified else "HIGH",
                "native_severity": "VERIFIED" if verified else "UNVERIFIED",
                "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                "owasp": None,
                "confidence": "high" if verified else "medium",
                "category": "secret",
                "code": "",  # never render the matched line - risks re-leaking the secret
                "fingerprint": _fingerprint("trufflehog", detector, file_path, line_no, redacted),
                "fix": None,
                "references": [],
                "source": "AccuKnox Secrets",
            })
    meta = {"repo": None, "sha": None, "ref": None, "ai_analysis": False}
    return findings, meta


def load_findings_gitleaks_sarif(path, changed_files=None):
    """Gitleaks `--report-format sarif` output: SARIF 2.1.0
    (runs[].results[].locations[].physicalLocation) - see scan/secret.py's
    _build_gitleaks_args, which always requests SARIF unless a custom
    --command overrides it.

    Gitleaks doesn't emit a severity/level per result the way Checkov emits
    null - rather than fabricate a native tier that may not exist, every
    finding here is treated as HIGH: unlike an IaC misconfig, a
    regex/entropy-matched secret is inherently risk-relevant even
    unconfirmed, so - unlike Checkov's UNKNOWN - it isn't excluded from the
    default quality gate."""
    with open(path) as f:
        data = json.load(f)

    findings = []
    for run in data.get("runs", []):
        for r in run.get("results", []):
            locations = r.get("locations") or [{}]
            loc = (locations[0].get("physicalLocation") or {})
            file_path = (loc.get("artifactLocation") or {}).get("uri", "")
            if changed_files is not None and file_path not in changed_files:
                continue
            region = loc.get("region") or {}
            start_line = region.get("startLine") or 1
            end_line = region.get("endLine") or start_line
            rule_id = r.get("ruleId", "secret")
            message = ((r.get("message") or {}).get("text")
                       or f"Possible secret detected ({rule_id}) - review before dismissing.")

            findings.append({
                "rule_id": rule_id,
                "path": file_path,
                "start_line": max(start_line, 1),
                "end_line": max(end_line, 1),
                "message": message,
                "severity": "HIGH",
                "native_severity": "UNKNOWN",
                "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                "owasp": None,
                "confidence": None,
                "category": "secret",
                "code": "",  # never render the matched snippet - risks re-leaking the secret
                "fingerprint": _fingerprint("gitleaks", rule_id, file_path, start_line),
                "fix": None,
                "references": [],
                "source": "AccuKnox Secrets",
            })
    meta = {"repo": None, "sha": None, "ref": None, "ai_analysis": False}
    return findings, meta


def load_findings_secret(path, changed_files=None):
    """Dispatches by extension - matches SecretScanner.result_file's own
    split (results.jsonl for TruffleHog, results.json for Gitleaks)."""
    if path.lower().endswith(".jsonl"):
        return load_findings_trufflehog_jsonl(path, changed_files)
    return load_findings_gitleaks_sarif(path, changed_files)


def load_findings_quality(path, changed_files=None):
    """Code-quality review JSON: {"comments": [{"path", "content", "start_line",
    "end_line", "category", "severity", "suggestion_code"}]}.

    Severity is capped at MEDIUM: quality feedback is advisory and must never
    trip the CRITICAL/HIGH gate that security findings drive."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for c in data.get("comments") or []:
        fpath = c.get("path", "")
        if not fpath or (changed_files is not None and fpath not in changed_files):
            continue
        # Security issues are already reported by the security scanners.
        if (c.get("category") or "").lower() == "security":
            continue
        start = max(int(c.get("start_line") or 1), 1)
        end = max(int(c.get("end_line") or start), start)
        native = (c.get("severity") or "low").upper()
        message = c.get("content", "")
        # The review tool's category is often just "other"; the first sentence
        # of the comment is a far better title for the inline comment and map.
        sentence = re.split(r"[.!?\n]", message.strip())[0]
        title = textwrap.shorten(sentence, 50, placeholder="…") or "Code quality"
        # Not "fix": that renders as a one-line suggestion block, which would
        # mangle a multi-line replacement when applied.
        if c.get("suggestion_code"):
            message += f"\n\n**Suggested change:**\n```\n{c['suggestion_code']}\n```"
        findings.append({
            "rule_id": title,
            "path": fpath,
            "start_line": start,
            "end_line": end,
            "message": message,
            "severity": "MEDIUM" if native in ("CRITICAL", "HIGH", "MEDIUM") else "LOW",
            "native_severity": native,
            "cwe": [],
            "owasp": None,
            "confidence": None,
            "category": "quality",
            "code": c.get("existing_code") or "",
            "fingerprint": _fingerprint("quality", fpath, start, c.get("content", "")),
            "fix": None,
            "references": [],
            "source": "AccuKnox Code Quality",
        })

    return findings, {"repo": None, "sha": None, "ref": None, "ai_analysis": True}


# scan type (as passed to `aspm-cli scan <type>`) -> loader. Explicit,
# because this CLI's own output filenames don't carry a type marker (unlike
# the AccuKnox-labeled <label>-<TYPE>-*.json files detect_loader() sniffs).
LOADERS_BY_SCANTYPE = {
    "sast": load_findings_sast,
    "sq-sast": load_findings_sast,
    "iac": load_findings_checkov,
    "sca": load_findings_trivy,
    "secret": load_findings_secret,
    "quality": load_findings_quality,
}

# Filename substring -> loader, first match wins. Fallback for callers not
# using LOADERS_BY_SCANTYPE (e.g. AccuKnox-labeled files from elsewhere).
ADAPTERS_BY_FILENAME = (
    ("-iac-", load_findings_checkov),
    ("-tr-", load_findings_trivy),
    ("-sca-", load_findings_trivy),
    ("-sg-", load_findings_sast),
    ("-sast-", load_findings_sast),
)


def detect_loader(path):
    name = os.path.basename(path).lower()
    for token, loader in ADAPTERS_BY_FILENAME:
        if token in name:
            return loader
    return load_findings_sast  # default: assume OpenGrep/SAST shape


def load_all_findings(paths, changed_files=None, scan_types=None):
    """Load + merge findings from one or more result files.

    `scan_types` is an optional list parallel to `paths` (the scan type each
    file came from, e.g. ["sast", "iac"]) - when given, that's authoritative
    over filename sniffing. Meta (repo/sha/ref/ai_analysis) is taken from
    whichever file reports a repo first."""
    all_findings = []
    meta = {"repo": None, "sha": None, "ref": None, "ai_analysis": False}
    scan_types = scan_types or [None] * len(paths)
    for path, scan_type in zip(paths, scan_types):
        loader = LOADERS_BY_SCANTYPE.get(scan_type) if scan_type else None
        loader = loader or detect_loader(path)
        findings, m = loader(path, changed_files)
        all_findings.extend(findings)
        if m.get("repo") and not meta.get("repo"):
            meta.update(m)
    return all_findings, meta
