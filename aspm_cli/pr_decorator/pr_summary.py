"""
Optional PR-level enrichment for the summary comment: a changed-files table
with touched symbol names, an LLM-generated narrative ("What this PR does" /
"Impact Analysis"), and an honest findings-by-file diagram.

All of this is presentation on top of the real findings, never load-bearing:
every function here degrades to None/"" (not a crash) when git or an LLM key
isn't available, and render_extra_sections() is safe to call with any mix of
missing pieces.

No fabricated call-graph analysis: the diagram shows PR -> changed file ->
one box per flagged line, coloured by its worst severity. Dotted lines only
follow line order inside a file - they are not data flow, which would need
real AST/call-graph analysis this repo doesn't have. A wrong diagram in a
security review is worse than no diagram.
"""
import json
import re

import requests

from aspm_cli.utils.git_info import GitInfo
from aspm_cli.utils.logger import Logger
from .remediation import DEFAULT_BASE_URL, DEFAULT_MODEL
from .render import DISPLAYED_SEVERITIES, SEVERITY_ICON, SEVERITY_ORDER

_MAX_FILES_IN_TABLE = 10
_MAX_FILES_IN_DIAGRAM = 8
_MAX_NODES_PER_FILE = 6
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
        out.append({"path": path, "added": added, "deleted": deleted,
                     "symbols": _extract_symbols(diff_text)})
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
    file_lines = "\n".join(
        f"- {r['path']} (+{r['added']} -{r['deleted']}): {', '.join(r['symbols']) or 'no named symbols detected'}"
        for r in file_changes[:20]
    )
    finding_lines = "\n".join(
        f"- {f['severity']} {f['rule_id']} in {f['path']}:{f['start_line']}" for f in findings[:20]
    ) or "none"
    return (
        "You are summarizing a pull request for a security review comment.\n\n"
        f"Changed files:\n{file_lines}\n\n"
        f"Security findings in this PR:\n{finding_lines}\n\n"
        "Reply with ONLY a JSON object, no markdown fences, no explanation, matching exactly:\n"
        '{"what_it_does": ["bullet", "..."], "impact": ["bullet", "..."]}\n\n'
        "3-6 short bullets each. what_it_does describes the functional changes only. "
        "impact covers functional AND security impact, referencing specific findings by "
        "file/rule where relevant - call out anything CRITICAL/HIGH explicitly."
    )


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
                  "max_tokens": 700},
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
        return data
    except Exception as e:
        logger.warning(f"PR narrative generation failed: {e}")
        return None


def render_narrative(narrative):
    if not narrative:
        return ""
    lines = []
    if narrative.get("what_it_does"):
        lines += ["### \U0001F4DD What This PR Does", ""]
        lines += [f"- {b}" for b in narrative["what_it_does"]]
        lines.append("")
    if narrative.get("impact"):
        lines += ["### \U0001F3AF Impact Analysis", ""]
        lines += [f"- {b}" for b in narrative["impact"]]
        lines.append("")
    return "\n".join(lines)


_SEV_CLASS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}
_CLASSDEFS = (
    "classDef crit fill:#d73a49,stroke:#86181d,color:#fff",
    "classDef high fill:#f66a0a,stroke:#b34700,color:#fff",
    "classDef med fill:#ffd33d,stroke:#b08800,color:#000",
    "classDef low fill:#e1e4e8,stroke:#959da5,color:#000",
)


def _mermaid_text(s, limit=44):
    """Mermaid labels break on quotes/brackets/angle brackets - strip them."""
    s = re.sub(r"[\"<>\[\]{}|]", "", str(s)).strip()
    return s if len(s) <= limit else s[:limit - 1] + "…"


def render_flow_diagram(findings):
    """One subgraph per changed file (worst first); inside, one box per flagged
    line coloured by its worst severity, e.g. 12 CVEs on requirements.txt:1
    collapse to a single "+11 more" box. Capped so GitHub's mermaid renderer
    and the comment size limit are never the failure point."""
    shown = [f for f in findings if f["severity"] in DISPLAYED_SEVERITIES]
    if not shown:
        return ""

    by_file = {}
    for f in shown:
        by_file.setdefault(f["path"], {}).setdefault(f["start_line"], []).append(f)

    def rank(items):
        return min(SEVERITY_ORDER.index(f["severity"]) for f in items)

    files = sorted(by_file.items(),
                   key=lambda kv: (min(rank(v) for v in kv[1].values()), kv[0]))

    lines = ["## \U0001F5FA️ Findings by File", "",
             "<details open>", "<summary><b>\U0001F4CC Findings map</b></summary>", "",
             "```mermaid", "graph TD", '  PR(["Pull Request"])']
    members = {cls: [] for cls in _SEV_CLASS.values()}

    for fi, (path, by_line) in enumerate(files[:_MAX_FILES_IN_DIAGRAM]):
        total = sum(len(v) for v in by_line.values())
        worst = min(rank(v) for v in by_line.values())
        lines.append(f'  subgraph F{fi}["{SEVERITY_ICON[SEVERITY_ORDER[worst]]} {_mermaid_text(path, 60)} · {total}"]')
        lines.append("    direction TB")
        # Worst-severity lines first when capping, then back to line order.
        picked = sorted(by_line.items(), key=lambda kv: (rank(kv[1]), kv[0]))[:_MAX_NODES_PER_FILE]
        picked.sort()
        ids = []
        for ni, (line_no, items) in enumerate(picked):
            items = sorted(items, key=lambda x: SEVERITY_ORDER.index(x["severity"]))
            top = items[0]
            more = f" +{len(items) - 1} more" if len(items) > 1 else ""
            label = f"{SEVERITY_ICON[top['severity']]} L{line_no} · {_mermaid_text(top['rule_id'].split('.')[-1])}{more}"
            nid = f"N{fi}_{ni}"
            lines.append(f'    {nid}["{label}"]')
            members[_SEV_CLASS[top["severity"]]].append(nid)
            ids.append(nid)
        hidden = len(by_line) - len(picked)
        if hidden > 0:
            lines.append(f'    M{fi}["… {hidden} more line(s)"]')
            members["low"].append(f"M{fi}")
            ids.append(f"M{fi}")
        lines.append("  end")
        if len(ids) > 1:
            lines.append("  " + " -.-> ".join(ids))
        lines.append(f"  PR --> F{fi}")

    remaining = len(files) - _MAX_FILES_IN_DIAGRAM
    if remaining > 0:
        lines.append(f'  PR --> MORE["… and {remaining} more file(s)"]')
        members["low"].append("MORE")

    lines += ["  " + d for d in _CLASSDEFS]
    lines += [f"  class {','.join(ids)} {cls}" for cls, ids in members.items() if ids]
    lines += ["```", "",
              f"{SEVERITY_ICON['CRITICAL']} Critical · {SEVERITY_ICON['HIGH']} High · "
              f"{SEVERITY_ICON['MEDIUM']} Medium · {SEVERITY_ICON['LOW']} Low "
              "— one box per flagged line, dotted lines follow line order within a file.",
              "", "</details>", ""]
    return "\n".join(lines)


def render_extra_sections(file_changes, narrative, findings):
    """Everything above Security Findings, in order. Each piece is already
    individually degrade-safe (empty string when its data is missing) - this
    just concatenates whatever came back."""
    parts = [render_file_changes_table(file_changes), render_narrative(narrative),
             render_flow_diagram(findings)]
    return "\n".join(p for p in parts if p)
