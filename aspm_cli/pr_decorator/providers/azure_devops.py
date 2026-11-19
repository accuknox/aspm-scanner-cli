from .base import PRProvider

_MSG = (
    "Azure DevOps PR decoration isn't implemented yet. "
    "ponytail: Azure Repos' PR threads API "
    "(POST .../pullrequests/{id}/threads) anchors inline comments via a "
    "threadContext object, a different shape than GitHub's review API this "
    "was ported from. Also needs 'Allow scripts to access OAuth token' "
    "enabled AND the Build Service identity granted 'Contribute to pull "
    "requests' in repo security settings - easy to half-configure and get a "
    "silent 403. detect.py doesn't return provider='azure_devops' yet - add "
    "BUILD_REASON=PullRequest + SYSTEM_PULLREQUEST_PULLREQUESTID detection "
    "there once this is filled in."
)


class AzureDevOpsProvider(PRProvider):
    def find_posted_fingerprints(self):
        raise NotImplementedError(_MSG)

    def post_or_update_summary(self, body, dry_run):
        raise NotImplementedError(_MSG)

    def post_review(self, body, event, comments, dry_run):
        raise NotImplementedError(_MSG)
