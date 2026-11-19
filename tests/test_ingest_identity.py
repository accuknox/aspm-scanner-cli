from aspm_cli.utils import ingest_identity as ii


def _no_git(monkeypatch):
    for name in ("get_repo_url", "get_branch_name", "get_commit_sha"):
        monkeypatch.setattr(ii.GitInfo, name, staticmethod(lambda: None))


def test_github_actions_environment(monkeypatch):
    _no_git(monkeypatch)
    env = {"GITHUB_REPOSITORY": "acme/api", "GITHUB_REF_NAME": "main", "GITHUB_SHA": "A" * 40,
           "GITHUB_RUN_ID": "42"}
    params = ii.collect_ingest_identity(env)
    assert params == {"repo_url": "https://github.com/acme/api", "branch": "main",
                      "commit_sha": "a" * 40,
                      "pipeline_run_url": "https://github.com/acme/api/actions/runs/42"}


def test_explicit_values_win_and_credentials_are_stripped(monkeypatch):
    _no_git(monkeypatch)
    env = {"ACCUKNOX_REPO_URL": "https://user:s3cret@gitlab.com/g/sub/proj.git", "GITHUB_REPOSITORY": "x/y",
           "ACCUKNOX_BRANCH": "refs/heads/release", "ACCUKNOX_APPLICATION": "Payments"}
    params = ii.collect_ingest_identity(env)
    assert params["repo_url"] == "https://gitlab.com/g/sub/proj.git"
    assert "s3cret" not in str(params)
    assert params["branch"] == "release" and params["application"] == "Payments"


def test_local_git_ssh_remote_and_detached_head(monkeypatch):
    monkeypatch.setattr(ii.GitInfo, "get_repo_url", staticmethod(lambda: "git@github.com:varendra007/agent-protocol.git"))
    monkeypatch.setattr(ii.GitInfo, "get_branch_name", staticmethod(lambda: "HEAD"))
    monkeypatch.setattr(ii.GitInfo, "get_commit_sha", staticmethod(lambda: "48ab2a045ba4" + "0" * 28))
    params = ii.collect_ingest_identity({})
    assert params["repo_url"] == "git@github.com:varendra007/agent-protocol.git"
    assert "branch" not in params  # detached HEAD is not a branch name
    assert params["commit_sha"].startswith("48ab2a045ba4")


def test_unusable_values_are_dropped_not_sent(monkeypatch):
    monkeypatch.setattr(ii.GitInfo, "get_repo_url", staticmethod(lambda: "/Users/me/local/repo"))
    monkeypatch.setattr(ii.GitInfo, "get_branch_name", staticmethod(lambda: "feature/a b"))
    monkeypatch.setattr(ii.GitInfo, "get_commit_sha", staticmethod(lambda: "not-a-sha"))
    assert ii.collect_ingest_identity({}) == {}


def test_opt_out(monkeypatch):
    _no_git(monkeypatch)
    assert ii.collect_ingest_identity({"GITHUB_REPOSITORY": "a/b", "ACCUKNOX_NO_REPO_IDENTITY": "true"}) == {}
