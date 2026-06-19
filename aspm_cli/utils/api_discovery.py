import os
import shlex
from typing import List, Optional

DEFAULT_RESULT_FILE = "results.json"
DOCKER_WORKDIR = "/workdir"


def parse_scan_path_from_command(command: str) -> str:
    """Extract -path / legacy --source from a code2api command string."""
    args = shlex.split(command or "-path .")
    if args and args[0] == "scan":
        return _legacy_scan_path(args)

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-path", "--path") and i + 1 < len(args):
            return args[i + 1]
        i += 1
    return "."


def _legacy_scan_path(args: List[str]) -> str:
    i = 1
    while i < len(args):
        if args[i] in ("--source", "-source") and i + 1 < len(args):
            return args[i + 1]
        i += 1
    return "."


def normalize_code2api_args(command: str, output_file: str = DEFAULT_RESULT_FILE) -> List[str]:
    """
    Build code2api CLI args: -path <dir> -output <file>.
    Accepts legacy placeholder commands: scan --source . --output results.json
    """
    args = shlex.split(command or "-path .")

    if args and args[0] == "scan":
        path = _legacy_scan_path(args)
        output = output_file
        i = 1
        while i < len(args):
            if args[i] in ("--output", "-output") and i + 1 < len(args):
                output = args[i + 1]
                i += 2
                continue
            i += 1
        return ["-path", path, "-output", output]

    normalized: List[str] = []
    has_path = False
    has_output = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-path", "--path"):
            if i + 1 < len(args):
                normalized.extend(["-path", args[i + 1]])
                has_path = True
                i += 2
                continue
        elif arg in ("-output", "--output"):
            if i + 1 < len(args):
                normalized.extend(["-output", args[i + 1]])
                has_output = True
                i += 2
                continue
        elif arg == "-verbose":
            normalized.append("-verbose")
            i += 1
            continue
        elif arg == "-version":
            normalized.append("-version")
            i += 1
            continue
        i += 1

    if not has_path:
        normalized.extend(["-path", "."])
    if not has_output:
        normalized.extend(["-output", output_file])
    return normalized


def normalize_code2api_args_for_docker(args: List[str], cwd: Optional[str] = None) -> List[str]:
    """Rewrite relative -path values for container /workdir mount."""
    cwd = cwd or os.getcwd()
    result = list(args)
    try:
        path_idx = result.index("-path")
    except ValueError:
        return result

    if path_idx + 1 >= len(result):
        return result

    target = result[path_idx + 1]
    if target in (".", ""):
        result[path_idx + 1] = DOCKER_WORKDIR
    elif not os.path.isabs(target) and not target.startswith(DOCKER_WORKDIR):
        result[path_idx + 1] = f"{DOCKER_WORKDIR}/{target.lstrip('./')}"

    try:
        output_idx = result.index("-output")
        if output_idx + 1 < len(result):
            output = result[output_idx + 1]
            if not os.path.isabs(output) and not output.startswith(DOCKER_WORKDIR):
                result[output_idx + 1] = f"{DOCKER_WORKDIR}/{output.lstrip('./')}"
    except ValueError:
        pass

    return result
