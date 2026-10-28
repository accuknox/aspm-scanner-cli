from abc import ABC, abstractmethod


class PRProvider(ABC):
    """Posts/updates a PR/MR review: one summary comment plus inline
    comments on the exact lines a finding was found, deduped by fingerprint
    across runs so a re-scan doesn't repost the same finding as a new thread.
    """

    def __init__(self, repo: str, pr_id: str, head_sha: str, token: str):
        self.repo = repo
        self.pr_id = pr_id
        self.head_sha = head_sha
        self.token = token

    @abstractmethod
    def find_posted_fingerprints(self) -> set:
        """Fingerprints already posted as inline comments in a prior run."""

    @abstractmethod
    def post_or_update_summary(self, body: str, dry_run: bool) -> None:
        """Create the summary comment, or update it in place if one from a
        prior run already exists (found via its hidden marker)."""

    @abstractmethod
    def post_review(self, body: str, event: str, comments: list, dry_run: bool) -> None:
        """Post the review: summary body, event (COMMENT/REQUEST_CHANGES),
        and inline comments as [{"path", "line", "body"}, ...]."""
