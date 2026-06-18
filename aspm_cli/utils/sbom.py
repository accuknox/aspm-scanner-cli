import os
import shlex
from typing import Any, Dict, List, Optional

SBOM_ALLOWED_SUBCOMMANDS = frozenset({"image", "rootfs", "filesystem", "fs"})
FILESYSTEM_SUBCOMMANDS = frozenset({"filesystem", "fs"})
DOCKER_WORKDIR = "/workdir"
ACCUKNOX_SCANNER_TOOL_NAME = "accuknox-container-scanner"
ACCUKNOX_SCANNER_VENDOR = "AccuKnox"


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


def scan_target_from_command(command: str) -> Optional[str]:
    """Return the scan target path argument after the subcommand, if present."""
    if not command:
        return None
    args = shlex.split(command)
    subcommand = parse_trivy_subcommand(command)
    if not subcommand:
        return None
    try:
        idx = args.index(subcommand)
        if idx + 1 < len(args):
            return args[idx + 1]
    except ValueError:
        return None
    return None


def derive_filesystem_component_display_name(
    command: str,
    cwd: Optional[str] = None,
) -> str:
    """
    Human-readable BOM root name from host cwd and --command target (e.g. repo or repo/utils).
    """
    try:
        cwd = cwd or os.getcwd()
    except OSError:
        cwd = "."
    repo = os.path.basename(os.path.abspath(cwd))
    target = scan_target_from_command(command)
    if not target or target in (".", ""):
        return repo
    if target == DOCKER_WORKDIR:
        return repo
    if target.startswith(f"{DOCKER_WORKDIR}/"):
        subpath = target[len(DOCKER_WORKDIR) + 1 :].strip("/")
    elif target.startswith("./"):
        subpath = target[2:].strip("/")
    elif _is_relative_scan_path(target):
        subpath = target.strip("/")
    else:
        subpath = os.path.basename(target.rstrip(os.sep))
    if subpath:
        return f"{repo}/{subpath}"
    return repo


def _should_rewrite_component_name(name: str) -> bool:
    if not name:
        return True
    if name in (".", ""):
        return True
    if name == DOCKER_WORKDIR or name.startswith(f"{DOCKER_WORKDIR}/"):
        return True
    return False


def _sanitize_property_name(name: str) -> str:
    if name.startswith("aquasecurity:trivy:"):
        return "accuknox:scanner:" + name[len("aquasecurity:trivy:") :]
    return name


def _sanitize_properties_list(properties: Optional[List[Dict[str, Any]]]) -> None:
    if not properties:
        return
    for prop in properties:
        if isinstance(prop, dict) and "name" in prop:
            prop["name"] = _sanitize_property_name(str(prop["name"]))


def sanitize_scanner_branding_from_bom(data: Dict[str, Any]) -> None:
    """Remove upstream scanner vendor/tool identifiers from CycloneDX output."""
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        return

    tools = metadata.get("tools")
    if isinstance(tools, dict):
        tools["components"] = [
            {
                "type": "application",
                "manufacturer": {"name": ACCUKNOX_SCANNER_VENDOR},
                "name": ACCUKNOX_SCANNER_TOOL_NAME,
            }
        ]

    component = metadata.get("component")
    if isinstance(component, dict):
        if component.get("group") == "aquasecurity":
            del component["group"]
        manufacturer = component.get("manufacturer")
        if isinstance(manufacturer, dict):
            mfg_name = str(manufacturer.get("name", ""))
            if "aqua" in mfg_name.lower():
                component["manufacturer"] = {"name": ACCUKNOX_SCANNER_VENDOR}
        _sanitize_properties_list(component.get("properties"))

    for comp in data.get("components") or []:
        if isinstance(comp, dict):
            _sanitize_properties_list(comp.get("properties"))


def apply_filesystem_component_display_name(data: Dict[str, Any], command: str) -> None:
    """Replace /workdir paths in metadata.component.name with host-relative display names."""
    if parse_trivy_subcommand(command) not in FILESYSTEM_SUBCOMMANDS:
        return
    display = derive_filesystem_component_display_name(command)
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        return
    component = metadata.get("component")
    if isinstance(component, dict):
        if _should_rewrite_component_name(str(component.get("name", ""))):
            component["name"] = display


def enrich_sbom_payload(
    data: Dict[str, Any],
    command: str,
    project_name: Optional[str],
    project_classifier: str,
) -> None:
    """Apply AccuKnox SBOM fields, human-readable paths, and branding sanitization."""
    if project_name:
        data["project_name"] = project_name
    data["project_classifier"] = project_classifier
    apply_filesystem_component_display_name(data, command)
    sanitize_scanner_branding_from_bom(data)


def validate_sbom_command(command: str) -> None:
    """Require a supported container scanner subcommand when generating SBOM."""
    subcommand = parse_trivy_subcommand(command)
    if subcommand not in SBOM_ALLOWED_SUBCOMMANDS:
        raise ValueError(
            "Invalid command for SBOM generation. "
            f"First argument must be one of: {', '.join(sorted(SBOM_ALLOWED_SUBCOMMANDS))}. "
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


def is_sbom_payload_empty(data: Any) -> bool:
    """Return True when CycloneDX payload has no meaningful BOM content."""
    if not isinstance(data, dict) or not data:
        return True
    components = data.get("components")
    if isinstance(components, list) and len(components) > 0:
        return False
    metadata = data.get("metadata")
    if isinstance(metadata, dict) and metadata.get("component"):
        return False
    return True


def append_sbom_scanner_flags(sanitized_args: List[str]) -> List[str]:
    """Ensure SBOM scans request package + license analysis for richer CycloneDX output."""
    if "--scanners" in sanitized_args:
        return sanitized_args
    result = list(sanitized_args)
    result.extend(["--scanners", "vuln,license"])
    return result
