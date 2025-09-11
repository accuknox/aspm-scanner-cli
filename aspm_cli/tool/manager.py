import platform
from pathlib import Path
import os


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


    TOOL_PATHS = {
        "iac": Path("iac"),
        "container": Path("container"),
        "secret": Path("secret"),
        "sq-sast": Path("sq-sast") / "bin" / "sonar-scanner",
        "dast": Path("dast") / "zap",
        "dast-java": Path("dast") / "java" / "bin",
        "sast": Path("sast") / "sast",
        "sast-rules": Path("sast") / "rules",
    }


    @staticmethod
    def get_path(name: str) -> str:
        if ToolManager._is_windows:
            raise ValueError("Non-container mode is not supported currently on Windows")

        """
        Returns the full OS-aware path under the AccuKnox install directory
        for the given tool/directory name. Raises an error if the path does not exist.
        """
        subpath = ToolManager.TOOL_PATHS.get(name)
        if not subpath:
            raise ValueError(f"Unknown tool or directory name: {name}")

        full_path = ToolManager._install_dir / subpath

        if not full_path.exists():
            raise FileNotFoundError(f"Tool not found. Please run `scanner tool install --type {name}`")

        return str(full_path)