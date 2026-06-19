import json
from typing import List


def append_skip_git_dir(args: List[str]) -> List[str]:
    """Ask Trivy not to walk .git during filesystem SCA scans."""
    if not args or "--skip-dirs" in args:
        return args
    return [args[0], "--skip-dirs", ".git", *args[1:]]


def normalize_sca_trivy_report(result_file: str) -> bool:
    """
    Trivy 0.69+ tags git checkouts as ArtifactType repository.
    AccuKnox SCA parsing expects filesystem.
    """
    with open(result_file, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("ArtifactType") != "repository":
        return False
    data["ArtifactType"] = "filesystem"
    with open(result_file, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    return True
