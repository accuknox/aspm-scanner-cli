"""Orchestrates one decorate-pr run: detect PR context -> load findings ->
render -> post via the matching provider. Mirrors PR-Decorator's
post_pr_review.py main(), split so it's callable from the CLI command
instead of parsed off sys.argv."""
import os

from aspm_cli.utils.git_info import GitInfo
from aspm_cli.utils.logger import Logger

from .adapters import load_all_findings
from .detect import detect_pr_context
from .pr_summary import build_file_changes, generate_pr_narrative, render_extra_sections
from .providers import PROVIDERS
from .remediation import DEFAULT_BASE_URL, DEFAULT_MODEL, enrich_with_remediation
from .render import compute_event, render_inline_comment, render_summary_comment


def _find_sast_path(result_paths, scan_types):
    """Native fix / AI remediation only make sense against the the scanner/SAST
    shaped file - pick it out of a possibly multi-scan-type file list."""
    if scan_types:
        for path, t in zip(result_paths, scan_types):
            if t in ("sast", "sq-sast"):
                return path
        return None
    for path in result_paths:
        name = path.lower()
        if "-sg-" in name or "-sast-" in name or name.endswith("results.json"):
            return path
    return None


def run(result_paths, scan_types=None, changed_files=None, mode="advisory",
        thresholds=None, dry_run=False, github_token=None,
        llm_api_key=None, llm_model=DEFAULT_MODEL, llm_base_url=DEFAULT_BASE_URL):
    logger = Logger.get_logger()

    ctx = detect_pr_context()
    if ctx is None:
        logger.info("Not a pull/merge request build - skipping PR decoration.")
        return 0

    provider_cls = PROVIDERS.get(ctx.provider)
    if provider_cls is None:
        logger.warning(f"No PR-decorator provider for '{ctx.provider}' yet - skipping.")
        return 0

    if changed_files is None and ctx.base_sha:
        diff = GitInfo.get_changed_files(ctx.base_sha, ctx.head_sha)
        if diff is not None:
            changed_files = set(diff)

    if llm_api_key:
        sast_path = _find_sast_path(result_paths, scan_types)
        if sast_path:
            enrich_with_remediation(sast_path, changed_files, llm_api_key, llm_model, llm_base_url)
        else:
            logger.debug("No SAST-shaped result file found - skipping AI remediation.")

    findings, meta = load_all_findings(result_paths, changed_files, scan_types)
    # Same finding reported twice (overlapping rules/engines) = one comment.
    findings = list({f["fingerprint"]: f for f in findings}.values())
    meta["pr_number"] = ctx.pr_id
    meta["ai_analysis"] = bool(llm_api_key)
    meta["mode"] = mode

    token = github_token or os.environ.get("GITHUB_TOKEN", "")
    if not dry_run and not token:
        logger.error("No token available to post the PR review. Pass --github-token, "
                      "set GITHUB_TOKEN, or use --dry-run.")
        return 1

    provider = provider_cls(repo=ctx.repo, pr_id=ctx.pr_id, head_sha=ctx.head_sha, token=token)

    # PR-level enrichment (changed-files table, AI narrative, findings-by-file
    # diagram) - each piece degrades to nothing on its own (no base_sha, no
    # LLM key, network failure), never blocks posting the real findings.
    file_changes = build_file_changes(ctx.base_sha, ctx.head_sha) if ctx.base_sha else None
    narrative = generate_pr_narrative(file_changes, findings, llm_api_key, llm_model, llm_base_url)
    extra_sections = render_extra_sections(file_changes, narrative, findings)

    summary_body = render_summary_comment(findings, meta, thresholds, extra_sections=extra_sections)
    provider.post_or_update_summary(summary_body, dry_run)

    # Dry run has no token guarantee and no real PR to check against, so it
    # can't know what's already posted - treat everything as new.
    posted_fps = set() if dry_run else provider.find_posted_fingerprints()
    # UNKNOWN findings (the scanner's unrated noise, see render.DISPLAYED_SEVERITIES)
    # don't get their own inline thread either - same reasoning as the summary.
    new_findings = [f for f in findings
                     if f["fingerprint"] not in posted_fps and f["severity"] != "UNKNOWN"]
    skipped = len([f for f in findings if f["severity"] != "UNKNOWN"]) - len(new_findings)

    event = compute_event(findings, mode)
    comments = [{"path": f["path"], "line": f["start_line"], "body": render_inline_comment(f)}
                for f in new_findings]

    if not comments and event != "REQUEST_CHANGES":
        logger.info(f"No new findings to post ({skipped} already have a review comment "
                     f"from a prior run) - skipping review.")
        return 0

    if skipped:
        logger.info(f"{skipped} finding(s) already posted in a prior run, skipped; "
                     f"{len(new_findings)} new inline comment(s).")

    # Short, not summary_body again: the summary issue comment is the one
    # "living" copy that gets updated in place every run. A review's own
    # body is never updated or deduped on a re-run - reusing summary_body
    # here would post the *entire* summary a second time in the PR timeline
    # today, and again on every future run (unbounded growth, since each
    # review is a new object, unlike the summary comment).
    displayed_total = len([f for f in findings if f["severity"] != "UNKNOWN"])
    review_body = (f"\U0001F6E1️ **AccuKnox Security Review** - {displayed_total} finding(s) "
                    f"({len(new_findings)} new in this run). See the summary comment above for the "
                    f"full breakdown.")

    provider.post_review(review_body, event, comments, dry_run)
    return 0
