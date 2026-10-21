"""
Optional PR-level enrichment for the summary comment: a changed-files table
with touched symbol names, an LLM-generated narrative ("What this PR does" /
"Impact Analysis"), and an honest findings-by-file diagram.

All of this is presentation on top of the real findings, never load-bearing:
every function here degrades to None/"" (not a crash) when git or an LLM key
isn't available, and render_extra_sections() is safe to call with any mix of
missing pieces.

No fabricated call-graph analysis: the diagram shows PR -> changed file ->
one box per flagged line, coloured by its worst severity. The edges are
containment, not data flow, which would need real AST/call-graph analysis
this repo doesn't have. A wrong diagram in a security review is worse than
no diagram.
"""
import json
import re

import requests

from aspm_cli.utils.git_info import GitInfo
from aspm_cli.utils.logger import Logger
from .remediation import DEFAULT_BASE_URL, DEFAULT_MODEL
from .render import DISPLAYED_SEVERITIES, SEVERITY_ICON, SEVERITY_ORDER

_MAX_FILES_IN_TABLE = 10
_MAX_FILES_IN_DIAGRAM = 5
_MAX_NODES_PER_FILE = 3
_EXCERPT_LINES = 25
_MAX_SYMBOLS_SHOWN = 5
_TIMEOUT = 30

# Added-line patterns for common languages/IaC, first match per line wins.
# Best-effort symbol extraction, not a parser - a line that doesn't match
# any of these just doesn't contribute a symbol name, nothing crashes.
_SYMBOL_PATTERNS = (
    re.compile(r"^\+\s*(?:async\s+)?def\s+(\w+)\s*\("),                      # Python
    re.compile(r"^\+\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\("),  # JS/TS
    re.compile(r"^\+\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\("),  # JS/TS arrow fn
    re.compile(r"^\+\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\("),                 # Go
    re.compile(r"^\+\s*resource\s+\"[\w-]+\"\s+\"([\w-]+)\""),               # Terraform
    re.compile(r"^\+\s*class\s+(\w+)"),                                     # Python/Java/JS class
)


def _extract_symbols(diff_text):
    seen = []
    for line in (diff_text or "").splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for pat in _SYMBOL_PATTERNS:
            m = pat.match(line)
            if m:
                name = m.group(1)
                if name not in seen:
                    seen.append(name)
                break
    return seen


def build_file_changes(base_sha, head_sha):
    """[{"path", "added", "deleted", "symbols": [...]}, ...] or None if the
    diff couldn't be computed (e.g. base_sha not fetched)."""
    rows = GitInfo.get_diff_numstat(base_sha, head_sha)
    if not rows:
        return None
    out = []
    for path, added, deleted in rows:
        diff_text = GitInfo.get_unified_diff_for_file(base_sha, head_sha, path)
        added_lines = [l[1:].rstrip()[:160] for l in (diff_text or "").splitlines()
                       if l.startswith("+") and not l.startswith("+++") and l[1:].strip()]
        out.append({"path": path, "added": added, "deleted": deleted,
                     "symbols": _extract_symbols(diff_text),
                     "excerpt": added_lines[:_EXCERPT_LINES]})
    return out


def render_file_changes_table(file_changes):
    if not file_changes:
        return ""
    lines = ["### \U0001F511 Key Changes at a Glance", "",
             "| File | Changes | Key Updates |", "|---|---|---|"]
    shown = file_changes[:_MAX_FILES_IN_TABLE]
    for r in shown:
        symbols = r["symbols"]
        if symbols:
            updates = ", ".join(symbols[:_MAX_SYMBOLS_SHOWN])
            if len(symbols) > _MAX_SYMBOLS_SHOWN:
                updates += "..."
        else:
            updates = "*code changes*"
        added = f"+{r['added']}" if r["added"] != "-" else "binary"
        deleted = f"-{r['deleted']}" if r["deleted"] != "-" else ""
        lines.append(f"| `{r['path']}` | {added} {deleted} | {updates} |")
    remaining = len(file_changes) - len(shown)
    if remaining > 0:
        lines.append(f"| ... | ... | *and {remaining} more file(s)* |")
    lines.append("")
    return "\n".join(lines)


def _build_narrative_prompt(file_changes, findings):
    # Never send the content of a file that has a secret finding to a third-party model.
    secret_paths = {f["path"] for f in findings if f.get("category") == "secret"}
    blocks = []
    for r in file_changes[:12]:
        head = f"### {r['path']} (+{r['added']} -{r['deleted']})"
        if r["symbols"]:
            head += f" defines: {', '.join(r['symbols'][:8])}"
        excerpt = r.get("excerpt") or []
        if r["path"] in secret_paths or not excerpt:
            blocks.append(head + "\n(changed lines not shown - describe only as a code/config change)")
        else:
            blocks.append(head + "\n" + "\n".join(f"+ {l}" for l in excerpt))
    ranked = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    finding_lines = "\n".join(
        f"- {f['severity']} {f['rule_id']} in {f['path']}:{f['start_line']} - "
        f"{' '.join(str(f.get('message', '')).split())[:110]}"
        for f in ranked[:25]
    ) or "none"
    return (
        "You are a senior application-security engineer writing the summary of a pull request "
        "review for the developer who opened it. Be specific, factual and useful; never "
        "invent behaviour the data does not show.\n\n"
        "Changed files (added lines only):\n" + "\n\n".join(blocks) + "\n\n"
        f"Scanner findings in this PR (worst first):\n{finding_lines}\n\n"
        "Reply with ONLY a JSON object, no markdown fences, no explanation, matching exactly:\n"
        '{"summary": "one sentence: what the PR does and its overall risk", '
        '"what_it_does": ["bullet"], '
        '"impact": [{"severity": "CRITICAL|HIGH|MEDIUM|LOW", "where": "path:line", '
        '"title": "5-9 word name of the risk", '
        '"risk": "1-2 sentences: how this could realistically be exploited or fail, and what is at stake", '
        '"action": "the concrete fix, e.g. the exact change or version", '
        '"effort": "low|medium|high"}]}\n\n'
        "Rules: what_it_does has 3-5 bullets describing ONLY what the added lines show, naming "
        "files/functions; if a file's lines are not shown say it is a code/config change and "
        "nothing more - never guess its purpose. impact has at most 6 entries, worst first, one "
        "per distinct risk (merge findings sharing a cause, e.g. several CVEs in one dependency "
        "file). 'where' must be a path from the findings. Do not restate counts."
    )


def _ground_severity(impact, findings):
    """The model describes risks; the scanner decides severity. Replace each row's
    severity with the worst finding at its path (and line, when it names one)."""
    for r in impact:
        if not isinstance(r, dict) or not r.get("where"):
            continue
        path, _, line = str(r["where"]).partition(":")
        line = int(line.split("-")[0]) if line.split("-")[0].isdigit() else None
        hits = [f for f in findings if f["path"] == path
                and f["severity"] in DISPLAYED_SEVERITIES
                and (line is None or f["start_line"] <= line <= f["end_line"])]
        if hits:
            r["severity"] = min((f["severity"] for f in hits), key=SEVERITY_ORDER.index)
    return impact


def generate_pr_narrative(file_changes, findings, api_key, model=None, base_url=None):
    """{"what_it_does": [...], "impact": [...]} or None - skipped (no key/no
    diff) or failed (bad response, network error). Never raises."""
    logger = Logger.get_logger()
    if not api_key or not file_changes:
        return None
    model = model or DEFAULT_MODEL
    base_url = base_url or DEFAULT_BASE_URL
    try:
        resp = requests.post(
            base_url,
            json={"model": model,
                  "messages": [{"role": "user", "content": _build_narrative_prompt(file_changes, findings)}],
                  "max_tokens": 1100},
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
                     "HTTP-Referer": "https://github.com/accuknox/aspm-scanner-cli",
                     "X-Title": "AccuKnox PR Decorator"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content).strip()
        data = json.loads(content)
        if not isinstance(data.get("what_it_does"), list) or not isinstance(data.get("impact"), list):
            raise ValueError(f"unexpected narrative shape: {data!r}")
        _ground_severity(data["impact"], findings)
        return data
    except Exception as e:
        logger.warning(f"PR narrative generation failed: {e}")
        return None


def _cell(text):
    """Table cells can't contain pipes or newlines."""
    return " ".join(str(text or "").replace("|", "/").split())


def render_narrative(narrative):
    if not narrative:
        return ""
    lines = []
    if narrative.get("what_it_does") or narrative.get("summary"):
        lines += ["### \U0001F4DD What This PR Does", ""]
        if narrative.get("summary"):
            lines += [f"_{_cell(narrative['summary'])}_", ""]
        lines += [f"- {b}" for b in narrative.get("what_it_does", [])]
        lines.append("")
    impact = narrative.get("impact") or []
    if impact:
        lines += ["### \U0001F3AF Impact Analysis", ""]
        if all(isinstance(r, dict) for r in impact):
            # Don't trust the model's ordering: worst severity first, stable otherwise.
            impact = sorted(impact, key=lambda r: SEVERITY_ORDER.index(str(r.get("severity", "")).upper())
                            if str(r.get("severity", "")).upper() in SEVERITY_ORDER else len(SEVERITY_ORDER))
            lines += ["_Ordered by risk - fix from the top. ⚡ marks a high-impact, low-effort fix._", ""]
            for r in impact:
                sev = str(r.get("severity", "")).upper()
                badge = f"{SEVERITY_ICON[sev]} **{sev}**" if sev in SEVERITY_ICON else "ℹ️ **INFO**"
                where = f" · `{_cell(r['where'])}`" if r.get("where") else ""
                title = _cell(r.get("title") or r.get("risk"))
                quick = " ⚡" if str(r.get("effort", "")).lower() == "low" and sev in ("CRITICAL", "HIGH") else ""
                lines.append(f"- {badge}{where} — **{title}**{quick}")
                if r.get("title") and r.get("risk"):
                    lines.append(f"  - **Why it matters:** {_cell(r['risk'])}")
                if r.get("action"):
                    effort = f" _(effort: {_cell(r['effort'])})_" if r.get("effort") else ""
                    lines.append(f"  - **Fix:** {_cell(r['action'])}{effort}")
        else:
            lines += [f"- {r}" for r in impact]
        lines.append("")
    return "\n".join(lines)




def _mermaid_text(s, limit=30):
    """Mermaid labels break on quotes/brackets/angle brackets - strip them."""
    s = re.sub(r"[\"<>\[\]{}|()]", "", str(s)).strip()
    return s if len(s) <= limit else s[:limit - 1] + "…"


def render_flow_diagram(findings):
    """Left-to-right tree: Pull Request -> changed file (with its per-severity
    counts) -> one box per flagged line, coloured by that line's worst
    severity; edges take the colour of what they lead to. Several findings on
    one line (12 CVEs on requirements.txt:1) collapse into one "+N" box.
    Capped so GitHub's mermaid renderer and the comment size limit are never
    the failure point."""
    shown = [f for f in findings if f["severity"] in DISPLAYED_SEVERITIES]
    if not shown:
        return ""

    by_file = {}
    for f in shown:
        by_file.setdefault(f["path"], {}).setdefault(f["start_line"], []).append(f)

    def rank(items):
        return min(SEVERITY_ORDER.index(f["severity"]) for f in items)

    files = sorted(by_file.items(), key=lambda kv: (min(rank(v) for v in kv[1].values()), kv[0]))

    lines = ["## \U0001F5FA️ Findings by File", "",
             "<details open>", "<summary><b>\U0001F4CC Findings map</b></summary>", "",
             "```mermaid", "pie showData title Findings by severity",
             *[f'  "{SEVERITY_ICON[sv]} {sv.title()}" : {n}'
               for sv in DISPLAYED_SEVERITIES if (n := sum(1 for f in shown if f["severity"] == sv))],
             "```", "",
             "```mermaid",
             '%%{init: {"flowchart": {"nodeSpacing": 12, "rankSpacing": 28, "padding": 6}}}%%',
             "graph LR",
             f'  PR(["<b>Pull Request</b><br/>{len(shown)} finding(s) · {len(files)} file(s)"])']

    for fi, (path, by_line) in enumerate(files[:_MAX_FILES_IN_DIAGRAM]):
        per_sev = {s: sum(1 for v in by_line.values() for f in v if f["severity"] == s)
                   for s in DISPLAYED_SEVERITIES}
        counts = " · ".join(f"{SEVERITY_ICON[s]} {n}" for s, n in per_sev.items() if n)
        lines.append(f'  F{fi}["<b>{_mermaid_text(path, 40)}</b><br/>{counts}"]')
        lines.append(f"  PR --> F{fi}")
        # Worst-severity lines first when capping, then back to line order.
        picked = sorted(by_line.items(), key=lambda kv: (rank(kv[1]), kv[0]))[:_MAX_NODES_PER_FILE]
        picked.sort()
        for ni, (line_no, items) in enumerate(picked):
            items = sorted(items, key=lambda x: SEVERITY_ORDER.index(x["severity"]))
            top = items[0]
            more = f" +{len(items) - 1} more" if len(items) > 1 else ""
            label = f"{SEVERITY_ICON[top['severity']]} L{line_no} · {_mermaid_text(top['rule_id'].split('.')[-1])}{more}"
            nid = f"N{fi}_{ni}"
            lines.append(f'  {nid}("{label}")')
            lines.append(f"  F{fi} --> {nid}")
        hidden = len(by_line) - len(picked)
        if hidden > 0:
            lines.append(f'  M{fi}("… {hidden} more line(s)")')
            lines.append(f"  F{fi} -.-> M{fi}")

    remaining = len(files) - _MAX_FILES_IN_DIAGRAM
    if remaining > 0:
        lines.append(f'  MORE("… and {remaining} more file(s)")')
        lines.append("  PR -.-> MORE")

    lines += ["```", "",
              f"{SEVERITY_ICON['CRITICAL']} Critical · {SEVERITY_ICON['HIGH']} High · "
              f"{SEVERITY_ICON['MEDIUM']} Medium · {SEVERITY_ICON['LOW']} Low "
              "— one box per flagged line, marked with its worst severity.",
              "", "</details>", ""]
    return "\n".join(lines)


def render_extra_sections(file_changes, narrative, findings):
    """Everything above Security Findings, in order. Each piece is already
    individually degrade-safe (empty string when its data is missing) - this
    just concatenates whatever came back."""
    parts = [render_file_changes_table(file_changes), render_narrative(narrative),
             render_flow_diagram(findings)]
    return "\n".join(p for p in parts if p)
