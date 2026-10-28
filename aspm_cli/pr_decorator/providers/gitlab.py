from .base import PRProvider

_MSG = (
    "GitLab MR decoration isn't implemented yet. "
    "ponytail: GitLab's Merge Request discussions API "
    "(POST /projects/:id/merge_requests/:iid/discussions) needs a position "
    "object per inline note (base/head/start SHA of the diff), a different "
    "shape than GitHub's review API this was ported from. detect.py also "
    "doesn't return provider='gitlab' yet - add CI_PIPELINE_SOURCE= "
    "merge_request_event detection there once this is filled in."
)


class GitLabProvider(PRProvider):
    def find_posted_fingerprints(self):
        raise NotImplementedError(_MSG)

    def post_or_update_summary(self, body, dry_run):
        raise NotImplementedError(_MSG)

    def post_review(self, body, event, comments, dry_run):
        raise NotImplementedError(_MSG)
