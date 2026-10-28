from .base import PRProvider

_MSG = (
    "Bitbucket PR decoration isn't implemented yet. "
    "ponytail: Bitbucket's PR comments API "
    "(POST /2.0/repositories/{workspace}/{repo}/pullrequests/{id}/comments) "
    "anchors inline comments via inline.path/inline.to, a different shape "
    "than GitHub's review API this was ported from. Also needs a manually "
    "provisioned App Password/Repository Access Token - Bitbucket Pipelines "
    "doesn't auto-inject a write-scoped token the way GITHUB_TOKEN does. "
    "detect.py doesn't return provider='bitbucket' yet - add BITBUCKET_PR_ID "
    "detection there once this is filled in."
)


class BitbucketProvider(PRProvider):
    def find_posted_fingerprints(self):
        raise NotImplementedError(_MSG)

    def post_or_update_summary(self, body, dry_run):
        raise NotImplementedError(_MSG)

    def post_review(self, body, event, comments, dry_run):
        raise NotImplementedError(_MSG)
