import json
import os
import re
import shlex
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from aspm_cli.utils.path_safety import resolve_path_within_root

MODEL_EXTENSIONS = frozenset({".pb", ".h5", ".keras", ".pth", ".pt", ".ckpt", ".npy", ".pkl"})
SKIP_DIR_NAMES = frozenset({".git", ".accuknox-modelscan", "node_modules", "__pycache__"})


def parse_scan_path_from_command(command: str) -> str:
    """Extract the -p/--path target from a modelscan command string."""
    args = shlex.split(command or "")
    if args and args[0] == "scan":
        args = args[1:]

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-p", "--path") and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("-p") and arg != "-p" and len(arg) > 2:
            return arg[2:]
        i += 1
    return "."


def normalize_modelscan_cli_args(command: str, output_file: str) -> List[str]:
    """Build modelscan CLI args: scan -p <path> -r json -o <output>."""
    args = shlex.split(command or "scan -p . -r json")
    if not args or args[0] != "scan":
        args = ["scan", *args]

    normalized: List[str] = ["scan"]
    i = 1
    has_path = False
    has_report = False
    has_output = False

    while i < len(args):
        arg = args[i]
        if arg in ("-p", "--path"):
            if i + 1 < len(args):
                normalized.extend([arg, args[i + 1]])
                has_path = True
                i += 2
                continue
        elif arg in ("-r", "--report-format"):
            if i + 1 < len(args):
                normalized.extend([arg, args[i + 1]])
                has_report = True
                i += 2
                continue
        elif arg in ("-o", "--output"):
            if i + 1 < len(args):
                normalized.extend([arg, args[i + 1]])
                has_output = True
                i += 2
                continue
        elif arg.startswith("-p") and len(arg) > 2:
            normalized.append(arg)
            has_path = True
            i += 1
            continue
        i += 1

    if not has_path:
        normalized.extend(["-p", "."])
    if not has_report:
        normalized.extend(["-r", "json"])
    if not has_output:
        normalized.extend(["-o", output_file])
    return normalized


def discover_model_files(scan_root: str, cwd: Optional[str] = None) -> List[str]:
    """Return model artifact paths under scan_root (or scan_root itself if it is a model file)."""
    cwd = cwd or os.getcwd()
    try:
        path = resolve_path_within_root(scan_root, cwd)
    except ValueError:
        return []

    if os.path.isfile(path):
        return [path] if _is_model_file(path) else []

    if not os.path.isdir(path):
        return []

    discovered: List[str] = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if _is_model_file(full_path):
                discovered.append(full_path)
    return sorted(discovered)


def _is_model_file(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in MODEL_EXTENSIONS


def _parse_github_model_id(repo_url: Optional[str]) -> Optional[str]:
    if not repo_url:
        return None
    repo_url = repo_url.strip().rstrip("/")
    if repo_url.startswith("git@"):
        match = re.match(r"git@[^:]+:([^/]+/[^/.]+)", repo_url)
        return match.group(1) if match else None
    if "://" in repo_url:
        parsed = urlparse(repo_url)
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) >= 2:
            repo = parts[-1]
            if repo.endswith(".git"):
                repo = repo[:-4]
            return f"{parts[-2]}/{repo}"
    if "/" in repo_url and " " not in repo_url:
        return repo_url.strip("/")
    return None


def derive_model_metadata(
    repo_url: Optional[str],
    commit_ref: Optional[str],
    model_name: Optional[str] = None,
    source_type: str = "github",
) -> Dict[str, str]:
    try:
        cwd_name = os.path.basename(os.path.abspath(os.getcwd()))
    except OSError:
        cwd_name = "local"
    model_id = _parse_github_model_id(repo_url) or repo_url or cwd_name
    repository_name = model_id.split("/")[-1] if "/" in model_id else model_id
    return {
        "name": model_name or repository_name or cwd_name,
        "model_id": model_id,
        "source_type": source_type,
        "repository_name": repository_name,
        "commit_ref": commit_ref or "local",
    }


def build_model_path(
    model_id: str,
    commit_ref: str,
    absolute_file_path: str,
    scan_root: str,
    cwd: Optional[str] = None,
) -> str:
    cwd = cwd or os.getcwd()
    scan_root_abs = os.path.normpath(
        scan_root if os.path.isabs(scan_root) else os.path.join(cwd, scan_root)
    )
    file_abs = os.path.normpath(absolute_file_path)
    try:
        relative = os.path.relpath(file_abs, scan_root_abs)
    except ValueError:
        relative = os.path.basename(file_abs)
    if relative.startswith(".."):
        relative = os.path.relpath(file_abs, cwd)
    return f"{model_id}/{commit_ref}/{relative}".replace(os.sep, "/")


def merge_modelscan_result(
    modelscan_output: Dict[str, Any],
    model_path: str,
) -> Dict[str, Any]:
    """Attach model_path to native modelscan JSON (issues[] preserved at top level)."""
    merged = dict(modelscan_output)
    merged["model_path"] = model_path
    return merged


def build_ondemand_modelscan_payload(
    modelscan_results: List[Dict[str, Any]],
    metadata: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "ondemand_modelscan": {
            "name": metadata["name"],
            "model_id": metadata["model_id"],
            "source_type": metadata["source_type"],
            "repository_name": metadata["repository_name"],
            "modelscan_results": modelscan_results,
        }
    }


def count_issues(modelscan_results: List[Dict[str, Any]]) -> int:
    total = 0
    for result in modelscan_results:
        issues = result.get("issues")
        if isinstance(issues, list):
            total += len(issues)
    return total


def load_modelscan_output(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {"issues": data}
