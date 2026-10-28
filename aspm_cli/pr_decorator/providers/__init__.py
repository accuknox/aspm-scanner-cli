from .github import GitHubProvider

# provider name (from detect.PRContext.provider) -> implementation.
# ponytail: gitlab/bitbucket/azure_devops land here once their providers.py
# stop raising NotImplementedError - detect.py only ever returns "github"
# today, so those classes exist purely as the interface to fill in next.
PROVIDERS = {
    "github": GitHubProvider,
}
