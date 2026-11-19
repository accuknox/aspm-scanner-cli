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


# ------------------------------------------------------------ branch in scan reports


def test_report_branch_is_the_pr_source_branch_not_the_detached_head(monkeypatch):
    monkeypatch.setattr(ii.GitInfo, "get_branch_name", staticmethod(lambda: "HEAD"))
    github_pr = {"GITHUB_HEAD_REF": "feature/login", "GITHUB_REF_NAME": "12/merge"}
    assert ii.detect_branch(github_pr) == "feature/login"
    assert ii.detect_branch({"CI_COMMIT_REF_NAME": "feature/login"}) == "feature/login"
    azure_pr = {"SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/feature/login",
                "BUILD_SOURCEBRANCH": "refs/pull/7/merge", "BUILD_SOURCEBRANCHNAME": "merge"}
    assert ii.detect_branch(azure_pr) == "feature/login"
    azure_push = {"BUILD_SOURCEBRANCH": "refs/heads/feature/login", "BUILD_SOURCEBRANCHNAME": "login"}
    assert ii.detect_branch(azure_push) == "feature/login"
    assert ii.detect_branch({"CHANGE_BRANCH": "feature/login", "BRANCH_NAME": "PR-12"}) == "feature/login"
    assert ii.detect_branch({"ACCUKNOX_BRANCH": "release", "GITHUB_HEAD_REF": "x"}) == "release"


def test_report_branch_outside_ci_is_gits_answer(monkeypatch):
    monkeypatch.setattr(ii.GitInfo, "get_branch_name", staticmethod(lambda: "my-branch"))
    assert ii.detect_branch({}) == "my-branch"
    monkeypatch.setattr(ii.GitInfo, "get_branch_name", staticmethod(lambda: None))
    assert ii.detect_branch({}) is None


def test_upload_branch_uses_the_same_detection(monkeypatch):
    _no_git(monkeypatch)
    env = {"GITHUB_REPOSITORY": "acme/api", "GITHUB_HEAD_REF": "feature/login", "GITHUB_REF_NAME": "12/merge"}
    assert ii.collect_ingest_identity(env)["branch"] == "feature/login"
    azure = {"BUILD_REPOSITORY_URI": "https://dev.azure.com/acme/web/_git/api",
             "BUILD_SOURCEBRANCH": "refs/heads/feature/login", "BUILD_SOURCEBRANCHNAME": "login"}
    assert ii.collect_ingest_identity(azure)["branch"] == "feature/login"
