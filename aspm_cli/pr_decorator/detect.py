"""
Detects whether the current run is a pull/merge-request build, and if so
against which provider - so `aspm-cli decorate-pr` is safe to add to the same
job/pipeline that also runs on a plain commit: not a PR/MR build -> no-op,
not an error.

GitHub Actions is the only wired-up provider today (see providers/github.py).
ponytail: add a _detect_gitlab_ci()/_detect_bitbucket()/_detect_azure_devops()
branch here once their providers/*.py exist - each CI sets its own env vars
for "this is a PR/MR build" (GitLab: CI_PIPELINE_SOURCE=merge_request_event +
CI_MERGE_REQUEST_IID; Bitbucket: BITBUCKET_PR_ID; Azure: BUILD_REASON=PullRequest
+ SYSTEM_PULLREQUEST_PULLREQUESTID), this function is the single place that
maps them to a PRContext.
"""
import json
import os
from dataclasses import dataclass
from typing import Optional

from aspm_cli.utils.logger import Logger


@dataclass
class PRContext:
    provider: str
    repo: str
    pr_id: str
    base_sha: Optional[str]
    head_sha: str


def detect_pr_context() -> Optional[PRContext]:
    if os.environ.get("GITHUB_EVENT_NAME") in ("pull_request", "pull_request_target"):
        return _detect_github_actions()
    return None


def _detect_github_actions() -> Optional[PRContext]:
    logger = Logger.get_logger()
    repo = os.environ.get("GITHUB_REPOSITORY")
    pr_id = os.environ.get("PR_NUMBER")
    head_sha = os.environ.get("HEAD_SHA") or os.environ.get("GITHUB_SHA")
    base_sha = None

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and os.path.exists(event_path):
        try:
            with open(event_path) as f:
                payload = json.load(f)
            pr = payload.get("pull_request") or {}
            pr_id = pr_id or str(pr.get("number") or "") or None
            base_sha = pr.get("base", {}).get("sha")
            head_sha = head_sha or pr.get("head", {}).get("sha")
        except (OSError, json.JSONDecodeError) as e:
            logger.debug(f"Could not read GITHUB_EVENT_PATH: {e}")

    if not repo or not pr_id:
        logger.warning(
            "pull_request event detected but GITHUB_REPOSITORY or the PR number "
            "is missing - skipping PR decoration."
        )
        return None

    return PRContext(provider="github", repo=repo, pr_id=pr_id, base_sha=base_sha,
                      head_sha=head_sha or "unknown")
