import json
from typing import List, Optional

GIT_SUFFIX = ".git"


def append_skip_git_dir(args: List[str]) -> List[str]:
    """Ask Trivy not to walk .git during filesystem SCA scans.

    Appended at the end, not after the subcommand: the docker path-normalizer
    rewrites the argument after the subcommand, so inserting it early makes it
    treat the flag as the scan target ("multiple targets cannot be specified").
    """
    if not args or "--skip-dirs" in args:
        return args
    return [*args, "--skip-dirs", GIT_SUFFIX]


def _clean_repo_url(url) -> str:
    url = (url or "").strip()
    if url.endswith(GIT_SUFFIX):
        url = url[: -len(GIT_SUFFIX)]
    return url


def prepare_sca_report(
    result_file: str,
    repo_url: Optional[str] = None,
    repo_branch: Optional[str] = None,
) -> None:
    """Normalize a Trivy filesystem report in place for AccuKnox SCA ingestion.

    Sets ArtifactName to "<RepoURL>:<Branch>" (the asset identity AccuKnox
    expects) instead of the in-container scan path, forces ArtifactType to
    "filesystem" (Trivy 0.69+ tags git checkouts as "repository"), strips the
    ".git" suffix, and drops the scanner version banner.

    Repo identity preference: CLI ``repo_url`` / ``repo_branch`` (when non-empty),
    otherwise Trivy Metadata. No-ops when neither source provides a RepoURL.
    """
    with open(result_file, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        return

    metadata = data.get("Metadata") or {}
    repo = _clean_repo_url(repo_url) or _clean_repo_url(metadata.get("RepoURL"))
    branch = (repo_branch or "").strip() or (metadata.get("Branch") or "").strip()
    if repo:
        data["ArtifactName"] = f"{repo}:{branch}" if branch else repo
        metadata["RepoURL"] = repo
        if branch:
            metadata["Branch"] = branch
        data["Metadata"] = metadata

    if data.get("ArtifactType") == "repository":
        data["ArtifactType"] = "filesystem"

    data.pop("Trivy", None)

    with open(result_file, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def normalize_sca_trivy_report(result_file: str) -> bool:
    """Deprecated: retained for backward compatibility. Prefer prepare_sca_report.

    Only flips ArtifactType repository -> filesystem.
    """
    with open(result_file, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("ArtifactType") != "repository":
        return False
    data["ArtifactType"] = "filesystem"
    with open(result_file, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    return True
