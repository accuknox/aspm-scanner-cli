"""Repository identity sent with an upload, so the scan lands under repository > branch.

Without it the backend creates an unparented asset that the Assets page does not list.
Resolution order for each value: explicit ``ACCUKNOX_*`` variable, CI-provider variables,
then the local git checkout. Anything that would not pass the backend's validation (a 400
rejects the whole upload) is dropped here instead. Set ``ACCUKNOX_NO_REPO_IDENTITY=true`` to opt out.
"""
from __future__ import annotations

import os
import re
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

from aspm_cli.utils.git_info import GitInfo
from aspm_cli.utils.logger import Logger

_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
_BRANCH_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f~^:?*\[\\]")
_SCP_LIKE = re.compile(r"^(?:[\w.-]+@)?(?P<host>[\w.-]+):(?!//)(?P<path>.+)$")


def _env(env: Mapping[str, str], *names: str) -> str:
    for name in names:
        value = (env.get(name) or "").strip()
        if value:
            return value
    return ""


def _clean_repo_url(url: str) -> str:
    """Drop embedded credentials; keep only URLs of the form host/owner/name."""
    value = url.strip()
    if not value or len(value) > 2048:
        return ""
    if "://" in value:
        parts = urlsplit(value)
        if not parts.hostname:
            return ""
        netloc = parts.hostname + (f":{parts.port}" if parts.port else "")
        value = urlunsplit((parts.scheme, netloc, parts.path, "", ""))
        host, path = parts.hostname, parts.path
    else:
        scp = _SCP_LIKE.match(value)
        host, path = (scp.group("host"), scp.group("path")) if scp else value.partition("/")[::2]
    segments = [segment for segment in path.strip("/").split("/") if segment]
    return value if "." in host and len(segments) >= 2 else ""


def derive_repository(repo_url: str) -> str:
    """``owner/name`` (nested groups kept) of a repository URL, '' when it cannot be derived.

    This is the form quality-gate policy scopes (``owner/name:branch``) match against.
    """
    value = (repo_url or "").strip()
    if not value:
        return ""
    if "://" in value:
        parts = urlsplit(value)
        host, path = parts.hostname or "", parts.path
    else:
        scp = _SCP_LIKE.match(value)
        host, path = (scp.group("host"), scp.group("path")) if scp else (value.partition("/")[0], value.partition("/")[2])
    segments = [segment for segment in path.strip("/").split("/") if segment]
    if "." not in host or len(segments) < 2:
        return ""
    segments[-1] = segments[-1].removesuffix(".git")
    return "/".join(segments) if segments[-1] else ""


def _clean_branch(branch: str) -> str:
    value = branch.strip().removeprefix("refs/heads/").strip("/")
    if not value or value == "HEAD" or len(value) > 255 or _BRANCH_FORBIDDEN.search(value):
        return ""
    return value


def _ci_repo_url(env: Mapping[str, str]) -> str:
    if env.get("GITHUB_REPOSITORY"):
        return f"{env.get('GITHUB_SERVER_URL', 'https://github.com').rstrip('/')}/{env['GITHUB_REPOSITORY']}"
    return _env(env, "CI_PROJECT_URL", "BITBUCKET_GIT_HTTP_ORIGIN", "BUILD_REPOSITORY_URI", "GIT_URL", "CHANGE_URL")


def _ci_branch(env: Mapping[str, str]) -> str:
    # For pull requests GitHub exposes the source branch separately from the merge ref.
    return _env(
        env, "GITHUB_HEAD_REF", "GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "BITBUCKET_BRANCH",
        "BUILD_SOURCEBRANCHNAME", "BRANCH_NAME", "GIT_BRANCH",
    ).removeprefix("origin/")


def _ci_pipeline_url(env: Mapping[str, str]) -> str:
    if env.get("GITHUB_RUN_ID") and env.get("GITHUB_REPOSITORY"):
        server = env.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
        return f"{server}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
    return _env(env, "CI_PIPELINE_URL", "CI_JOB_URL", "BUILD_URL")


def collect_ingest_identity(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Query parameters that place an upload under its repository and branch ({} when unknown)."""
    env = os.environ if env is None else env
    if (env.get("ACCUKNOX_NO_REPO_IDENTITY") or "").strip().lower() in ("1", "true", "yes"):
        return {}
    repo_url = _clean_repo_url(_env(env, "ACCUKNOX_REPO_URL") or _ci_repo_url(env) or GitInfo.get_repo_url() or "")
    params: dict[str, str] = {}
    if not repo_url:
        Logger.get_logger().debug("No repository URL detected; upload will not be attached to a repository.")
    else:
        params["repo_url"] = repo_url
        branch = _clean_branch(_env(env, "ACCUKNOX_BRANCH") or _ci_branch(env) or GitInfo.get_branch_name() or "")
        if branch:
            params["branch"] = branch
    sha = _env(env, "ACCUKNOX_COMMIT_SHA", "GITHUB_SHA", "CI_COMMIT_SHA", "BITBUCKET_COMMIT", "BUILD_SOURCEVERSION", "GIT_COMMIT")
    sha = sha or GitInfo.get_commit_sha() or ""
    if _SHA.match(sha):
        params["commit_sha"] = sha.lower()
    if application := _env(env, "ACCUKNOX_APPLICATION"):
        params["application"] = application
    if pipeline := (_env(env, "ACCUKNOX_PIPELINE_URL") or _ci_pipeline_url(env)):
        params["pipeline_run_url"] = pipeline
    return params
