"""GitHub PR provider - talks to the GitHub REST API with `requests`
(already a dependency here, see utils/common.py) instead of PR-Decorator's
original urllib, to match this codebase's conventions."""
import requests

from aspm_cli.utils.logger import Logger
from ..render import FINDING_MARKER_RE
from .base import PRProvider

API_ROOT = "https://api.github.com"
_TIMEOUT = 30
_BATCH = 25  # inline comments per review request


class GitHubProvider(PRProvider):
    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json"}

    def _get_all_pages(self, url):
        """GET a paginated GitHub list endpoint in full - default page size
        caps at 30, real PRs blow past that fast."""
        items = []
        page = 1
        while True:
            sep = "&" if "?" in url else "?"
            resp = requests.get(f"{url}{sep}per_page=100&page={page}", headers=self._headers(), timeout=_TIMEOUT)
            resp.raise_for_status()
            batch = resp.json()
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1

    def _find_existing_summary_comment(self):
        comments = self._get_all_pages(f"{API_ROOT}/repos/{self.repo}/issues/{self.pr_id}/comments")
        for c in comments:
            if "accuknox-pr-decorator:summary" in c.get("body", ""):
                return c["id"]
        return None

    def find_posted_fingerprints(self):
        comments = self._get_all_pages(f"{API_ROOT}/repos/{self.repo}/pulls/{self.pr_id}/comments")
        fps = set()
        for c in comments:
            m = FINDING_MARKER_RE.search(c.get("body", ""))
            if m:
                fps.add(m.group(1))
        return fps

    def post_or_update_summary(self, body, dry_run):
        logger = Logger.get_logger()
        existing_id = None if dry_run else self._find_existing_summary_comment()
        if existing_id:
            url = f"{API_ROOT}/repos/{self.repo}/issues/comments/{existing_id}"
            method = "PATCH"
        else:
            url = f"{API_ROOT}/repos/{self.repo}/issues/{self.pr_id}/comments"
            method = "POST"

        if dry_run:
            logger.info(f"[DRY RUN] {method} {url}")
            return

        resp = requests.request(method, url, json={"body": body}, headers=self._headers(), timeout=_TIMEOUT)
        resp.raise_for_status()
        logger.info(f"Summary comment {'updated' if existing_id else 'created'}: {resp.status_code}")

    def post_review(self, body, event, comments, dry_run):
        logger = Logger.get_logger()
        url = f"{API_ROOT}/repos/{self.repo}/pulls/{self.pr_id}/reviews"

        if dry_run:
            logger.info(f"[DRY RUN] POST {url} ({len(comments)} inline comment(s), event={event})")
            return

        # Big reviews can 504 even though GitHub went on to create them, so post
        # inline comments in small batches and treat a 5xx/timeout on a batch as
        # a warning: the next run's fingerprint dedup re-posts anything lost.
        batches = [comments[i:i + _BATCH] for i in range(0, len(comments), _BATCH)] or [[]]
        for n, batch in enumerate(batches):
            payload = {"commit_id": self.head_sha, "body": body if n == 0 else "(continued)",
                       "event": event if n == 0 else "COMMENT", "comments": batch}
            try:
                resp = requests.post(url, json=payload, headers=self._headers(), timeout=_TIMEOUT)
                if resp.status_code == 422 and batch:
                    # One inline line outside the PR diff makes GitHub reject the whole
                    # review. Post the review body alone, then each comment on its own so
                    # only the unresolvable ones are lost, not the whole batch.
                    logger.warning(f"GitHub rejected a batch of {len(batch)} inline comment(s) (422) - "
                                   f"retrying them one by one.")
                    payload["comments"] = []
                    resp = requests.post(url, json=payload, headers=self._headers(), timeout=_TIMEOUT)
                    skipped = self._post_comments_individually(batch)
                    if skipped:
                        logger.warning(f"{skipped} inline comment(s) skipped: their line is not part of the PR diff.")
                if resp.status_code >= 500:
                    logger.warning(f"GitHub returned {resp.status_code} for review batch {n + 1}/"
                                   f"{len(batches)}; it may still have been created. Continuing.")
                    continue
                resp.raise_for_status()
                logger.info(f"Review batch {n + 1}/{len(batches)} posted: {resp.status_code}")
            except requests.exceptions.Timeout:
                logger.warning(f"Timed out posting review batch {n + 1}/{len(batches)}; continuing.")

    def _post_comments_individually(self, comments):
        """Returns how many GitHub refused (a line outside the diff is a 422)."""
        url = f"{API_ROOT}/repos/{self.repo}/pulls/{self.pr_id}/comments"
        skipped = 0
        for c in comments:
            payload = {"body": c["body"], "commit_id": self.head_sha, "path": c["path"],
                       "line": c["line"], "side": "RIGHT"}
            try:
                resp = requests.post(url, json=payload, headers=self._headers(), timeout=_TIMEOUT)
            except requests.exceptions.RequestException:
                skipped += 1
                continue
            if resp.status_code >= 300:
                skipped += 1
        return skipped
