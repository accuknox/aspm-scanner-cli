import os
import sys
from pathlib import Path
from typing import List, Optional

# Subcommands that inspect container images or rootfs archives via the Docker API.
_TRIVY_IMAGE_SUBCOMMANDS = frozenset({"image", "rootfs", "container", "i", "vm"})


def platform_name() -> str:
    """Human-readable OS name for error messages."""
    if sys.platform == "win32":
        return "Windows"
    if sys.platform == "darwin":
        return "macOS"
    return "Linux"


def cpu_arch() -> str:
    """
    Normalize CPU architecture for tool downloads.
    Returns ``arm64`` (Apple Silicon / aarch64) or ``x86_64`` (Intel / amd64).
    """
    machine = os.uname().machine.lower() if hasattr(os, "uname") else ""
    if not machine:
        import platform as py_platform
        machine = py_platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64"
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    raise ValueError(f"Unsupported CPU architecture: {machine}")


def local_tool_install_supported() -> bool:
    """Native local scanner tools are supported on Linux and macOS (Intel + Apple Silicon)."""
    return sys.platform.startswith("linux") or sys.platform == "darwin"


def host_path_for_docker_volume(path: str) -> str:
    """Normalize a host path for ``docker run -v`` (Docker Desktop on Windows needs forward slashes)."""
    resolved = str(Path(path).resolve())
    if sys.platform == "win32":
        return resolved.replace("\\", "/")
    return resolved


def docker_volume_mount(host_path: str, container_path: str) -> List[str]:
    return ["-v", f"{host_path_for_docker_volume(host_path)}:{container_path}"]


def docker_workdir_mount(workdir: str = "/workdir", host_path: Optional[str] = None) -> List[str]:
    host = host_path or os.getcwd()
    return [
        *docker_volume_mount(host, workdir),
        "--workdir",
        workdir,
    ]


def docker_socket_mount_args() -> List[str]:
    """Mount the Docker socket so in-container scanners can reach the host daemon."""
    if sys.platform == "win32":
        return ["-v", r"\\.\pipe\docker_engine:\\.\pipe\docker_engine"]
    return ["-v", "/var/run/docker.sock:/var/run/docker.sock"]


def trivy_scan_needs_docker_socket(scan_args: List[str]) -> bool:
    if not scan_args:
        return False
    return scan_args[0] in _TRIVY_IMAGE_SUBCOMMANDS


def build_docker_run_prefix(
    *,
    workdir: str = "/workdir",
    host_path: Optional[str] = None,
    mount_docker_socket: bool = False,
) -> List[str]:
    cmd = ["docker", "run", "--rm"]
    if mount_docker_socket:
        cmd.extend(docker_socket_mount_args())
    cmd.extend(docker_workdir_mount(workdir, host_path))
    return cmd
