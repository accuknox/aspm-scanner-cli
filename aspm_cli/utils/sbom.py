import os
import shlex
from typing import List, Optional, Tuple

SBOM_ALLOWED_SUBCOMMANDS = frozenset({"image", "rootfs", "filesystem", "fs"})
FILESYSTEM_SUBCOMMANDS = frozenset({"filesystem", "fs"})
DOCKER_WORKDIR = "/workdir"


def parse_trivy_subcommand(command: str) -> Optional[str]:
    """Return the first positional Trivy subcommand, skipping leading flags."""
    if not command:
        return None
    args = shlex.split(command)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            if arg in ("-f", "--format", "-o", "--output", "-s", "--severity") and i + 1 < len(args):
                i += 2
                continue
            i += 1
            continue
        return arg
    return None


def derive_sbom_classifier(command: str) -> str:
    """Map Trivy subcommand to AccuKnox project_classifier for SBOM enrichment."""
    subcommand = parse_trivy_subcommand(command)
    if subcommand in FILESYSTEM_SUBCOMMANDS:
        return "application"
    return "container"


def resolve_project_name(cli_value: Optional[str] = None) -> Optional[str]:
    """Resolve project name: CLI -> ACCUKNOX_PROJECT_NAME -> ACCUKNOX_PROJECT."""
    if cli_value:
        return cli_value
    if "ACCUKNOX_PROJECT_NAME" in os.environ:
        return os.environ["ACCUKNOX_PROJECT_NAME"]
    if "ACCUKNOX_PROJECT" in os.environ:
        return os.environ["ACCUKNOX_PROJECT"]
    return None


def validate_sbom_command(command: str) -> None:
    """Require a supported Trivy subcommand when generating SBOM."""
    subcommand = parse_trivy_subcommand(command)
    if subcommand not in SBOM_ALLOWED_SUBCOMMANDS:
        raise ValueError(
            "Invalid Trivy command for SBOM generation. "
            f"First subcommand must be one of: {', '.join(sorted(SBOM_ALLOWED_SUBCOMMANDS))}. "
            "Examples: 'image nginx:latest' (container SBOM), 'filesystem .' (application SBOM)."
        )


def _is_relative_scan_path(path: str) -> bool:
    return not path.startswith("/")


def _normalize_path_component(path: str) -> str:
    path = path.strip()
    if path in (".", ""):
        return DOCKER_WORKDIR
    if path.startswith("./"):
        path = path[2:]
    return f"{DOCKER_WORKDIR}/{path}"


def normalize_filesystem_args_for_docker(args: List[str]) -> List[str]:
    """
    Rewrite relative filesystem/fs scan targets to /workdir paths for container mode.
    Leaves paths already under /workdir unchanged.
    """
    if not args:
        return args
    subcommand = args[0]
    if subcommand not in FILESYSTEM_SUBCOMMANDS or len(args) < 2:
        return args

    result = list(args)
    target = result[1]
    if target.startswith(f"{DOCKER_WORKDIR}") or target == DOCKER_WORKDIR:
        return result
    if _is_relative_scan_path(target):
        result[1] = _normalize_path_component(target)
    return result


def normalize_sbom_args_for_docker(command: str, sanitized_args: List[str]) -> List[str]:
    """Apply docker path normalization when building SBOM args in container mode."""
    subcommand = parse_trivy_subcommand(command)
    if subcommand in FILESYSTEM_SUBCOMMANDS:
        return normalize_filesystem_args_for_docker(sanitized_args)
    return sanitized_args
