import platform
from pathlib import Path
import os

from aspm_cli.utils.docker_runtime import local_tool_install_supported, platform_name


class ToolManager:
    """
    Static helper class to get OS-aware paths under the AccuKnox install directory.
    """

    # Determine OS
    _system = platform.system()
    _is_windows = _system == "Windows"

    if _is_windows:
        # Windows path
        _root_dir = Path(os.getenv("USERPROFILE")) / "AppData" / "Local" / "Programs" / "AccuKnox"
        _root_dir.mkdir(parents=True, exist_ok=True)
    else:
        # Linux global and fallback path
        _global_install_dir = Path("/") / "usr" / "share" / "accuknox-aspm-scanner" / "tools"
        _fallback_dir = Path.home() / ".local" / "bin" / "accuknox"
        _root_dir = _global_install_dir if _global_install_dir.exists() else _fallback_dir

        if not _root_dir.exists() and _root_dir == _fallback_dir:
            _root_dir.mkdir(parents=True, exist_ok=True)

    # Backward compatibility alias
    _install_dir = _root_dir

    # Unix layout (no extension). Windows resolves .exe / .bat in get_path().
    TOOL_PATHS = {
        "iac": Path("iac"),
        "container": Path("container"),
        "secret": Path("secret"),
        "sq-sast": Path("sq-sast") / "bin" / "sonar-scanner",
        "dast": Path("dast") / "zap",
        "dast-java": Path("dast") / "java" / "bin",
        "sast": Path("sast") / "sast",
        "sast-rules": Path("sast") / "rules",
        "codeassure": Path("codeassure") / "codeassure",
        "gitleaks": Path("gitleaks"),
        "api-discovery": Path("code2api"),
    }

    @staticmethod
    def _resolve_windows_path(full_path: Path) -> Path:
        """Prefer .exe / .bat companions for Windows scanner binaries."""
        if full_path.exists():
            return full_path
        for suffix in (".exe", ".bat", ".cmd"):
            candidate = full_path.with_suffix(suffix)
            if candidate.exists():
                return candidate
        # sonar-scanner lives as sonar-scanner.bat on Windows
        bat = Path(str(full_path) + ".bat")
        if bat.exists():
            return bat
        return full_path

    @staticmethod
    def get_path(name: str) -> str:
        """
        Returns the full OS-aware path under the AccuKnox install directory
        for the given tool/directory name. Raises an error if the path does not exist.
        """
        if not local_tool_install_supported():
            raise ValueError(
                f"Local (non-container) scan mode is not supported on {platform_name()}. "
                "Install Docker and pass --container-mode, or run "
                "`accuknox-aspm-scanner tool install --type <scanner>` on Linux, macOS, or Windows."
            )

        subpath = ToolManager.TOOL_PATHS.get(name)
        if not subpath:
            raise ValueError(f"Unknown tool or directory name: {name}")

        full_path = ToolManager._install_dir / subpath
        if ToolManager._is_windows:
            full_path = ToolManager._resolve_windows_path(full_path)

        if not full_path.exists():
            raise FileNotFoundError(f"Tool not found. Please run `scanner tool install --type {name}`")

        return str(full_path)
