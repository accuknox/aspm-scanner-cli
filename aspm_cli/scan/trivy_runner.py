import json
import os
import re
import shlex
import subprocess
from typing import List, Optional, Tuple

from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import config, docker_pull
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.subprocess_utils import run_scan_subprocess
from aspm_cli.utils.sca_prepare import append_skip_git_dir, prepare_sca_report
from aspm_cli.utils.docker_runtime import (
    build_docker_run_prefix,
    trivy_scan_needs_docker_socket,
)
from aspm_cli.utils.sbom import (
    FILESYSTEM_SUBCOMMANDS,
    normalize_filesystem_args_for_docker,
    parse_trivy_subcommand,
)

DEFAULT_TRIVY_IMAGE = "public.ecr.aws/k9v9d5v2/accuknox/trivy:0.69.3"
SCA_ALLOWED_SUBCOMMANDS = frozenset({"filesystem", "fs", "rootfs"})


def get_trivy_image() -> str:
    return os.getenv("SCAN_IMAGE", DEFAULT_TRIVY_IMAGE)


def validate_sca_command(command: str) -> None:
    subcommand = parse_trivy_subcommand(command)
    if subcommand not in SCA_ALLOWED_SUBCOMMANDS:
        raise ValueError(
            "Invalid command for SCA scan. "
            f"First argument must be one of: {', '.join(sorted(SCA_ALLOWED_SUBCOMMANDS))}. "
            "Example: 'fs .'"
        )


def build_trivy_vuln_args(
    command: str,
    result_file: str,
    cli_severity: Optional[str] = None,
) -> Tuple[Optional[str], List[str]]:
    """Parse Trivy command, strip conflicting flags, enforce JSON vuln output."""
    flags_to_strip = {"-s", "--severity", "-o", "--output", "-f", "--format", "--exit-code", "--quiet"}
    severity_threshold = None
    original_args = shlex.split(command or "")
    sanitized_args = []

    i = 0
    while i < len(original_args):
        arg = original_args[i]
        if arg in flags_to_strip:
            if arg in ("-s", "--severity") and i + 1 < len(original_args):
                severity_threshold = original_args[i + 1]
            i += 2
            continue
        sanitized_args.append(arg)
        i += 1

    sanitized_args.extend(["--quiet", "--exit-code", "1", "-f", "json", "-o", result_file])
    if severity_threshold is None and cli_severity:
        severity_threshold = cli_severity
    return severity_threshold, sanitized_args


def normalize_sca_args_for_docker(command: str, sanitized_args: List[str]) -> List[str]:
    subcommand = parse_trivy_subcommand(command)
    if subcommand in FILESYSTEM_SUBCOMMANDS:
        return normalize_filesystem_args_for_docker(sanitized_args)
    return sanitized_args


def build_trivy_scan_command(
    container_mode: bool,
    scan_args: List[str],
    image: Optional[str] = None,
) -> List[str]:
    image = image or get_trivy_image()
    if not container_mode:
        return [ToolManager.get_path("container"), *scan_args]

    cmd = build_docker_run_prefix(
        workdir="/workdir",
        mount_docker_socket=trivy_scan_needs_docker_socket(scan_args),
    )
    cmd.append(image)
    cmd.extend(scan_args)
    return cmd


def _fix_result_file_permissions_if_docker(container_mode: bool, result_file: str) -> None:
    """chmod the root-owned Trivy output so the host can rewrite it in place.

    In container mode Trivy runs as root; without this the in-place report
    normalization fails with PermissionError. Mirrors the SAST/IaC scanners.
    """
    if not container_mode:
        return
    try:
        subprocess.run(
            [
                *build_docker_run_prefix(workdir="/workdir"),
                "--entrypoint", "sh",
                get_trivy_image(),
                "-c", f"chmod 666 {os.path.basename(result_file)}",
            ],
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        Logger.get_logger().debug(f"Could not fix SCA result file permissions: {exc}")


def sanitize_trivy_log(text: str) -> str:
    return re.sub(r"trivy|aquasecurity|aqua security", "[scanner]", text, flags=re.IGNORECASE)


def severity_threshold_met(result_file: str, severity_threshold: List[str]) -> bool:
    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            if vuln.get("Severity", "").upper() in severity_threshold:
                return True
    return False


def run_trivy_vuln_scan(
    command: str,
    container_mode: bool,
    result_file: str = "./results.json",
    validate_command=None,
    cli_severity: Optional[str] = None,
    sca_mode: bool = False,
) -> Tuple[int, Optional[str]]:
    if validate_command:
        validate_command(command)

    if container_mode:
        docker_pull(get_trivy_image())

    severity_threshold, sanitized_args = build_trivy_vuln_args(
        command, result_file, cli_severity=cli_severity
    )
    if sca_mode:
        sanitized_args = append_skip_git_dir(sanitized_args)
    if container_mode:
        sanitized_args = normalize_sca_args_for_docker(command, sanitized_args)

    if os.path.exists(result_file):
        os.remove(result_file)

    scan_cmd = build_trivy_scan_command(container_mode, sanitized_args)
    Logger.get_logger().debug(f"Running Trivy vuln scan: {' '.join(scan_cmd)}")
    try:
        result = run_scan_subprocess(scan_cmd)
    except subprocess.TimeoutExpired:
        Logger.get_logger().error("Trivy scan timed out")
        return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

    if result.stdout:
        Logger.get_logger().debug(sanitize_trivy_log(result.stdout))
        if "--help" in (command or ""):
            from colorama import Fore
            Logger.log_with_color("INFO", sanitize_trivy_log(result.stdout), Fore.WHITE)
            return config.PASS_RETURN_CODE, None
    if result.stderr:
        Logger.get_logger().error(sanitize_trivy_log(result.stderr))

    if not os.path.exists(result_file):
        return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

    if sca_mode:
        _fix_result_file_permissions_if_docker(container_mode, result_file)
        prepare_sca_report(result_file)
        Logger.get_logger().debug(
            "SCA: finalized report identity (ArtifactName/type) for platform parsing"
        )

    thresholds = [
        s.strip().upper()
        for s in (severity_threshold or "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL").split(",")
    ]
    if severity_threshold_met(result_file, thresholds):
        Logger.get_logger().error(
            f"Vulnerabilities matching severities: {', '.join(thresholds)} found."
        )
        return 1, result_file

    return 0, result_file
