import platform
from pathlib import Path
import os


class ToolManager:
    """
    Static helper class to get OS-aware paths under the AccuKnox install directory.
    """

    # Determine OS and install directory
    _system = platform.system()
    _is_windows = _system == "Windows"
    _install_dir = (Path(os.getenv("USERPROFILE")) / "AppData" / "Local" / "Programs" / "AccuKnox"
                    if _is_windows else Path.home() / ".local" / "bin" / "accuknox")
    _install_dir.mkdir(parents=True, exist_ok=True)

    # OS-aware tool paths
    if _is_windows:
        raise ValueError("Non-container mode is not supported currently on Windows")
    else:  # Linux
        TOOL_PATHS = {
            "iac": Path("iac"),
            "container": Path("container"),
            "secret": Path("secret"),
            "sq-sast": Path("sq-sast") / "bin" / "sonar-scanner",
            "sast": Path("sast") / "sast",
            "sast-rules": Path("sast") / "rules",
        }

    @staticmethod
    def get_path(name: str) -> str:
        """
        Returns the full OS-aware path under the AccuKnox install directory
        for the given tool/directory name. Raises an error if the path does not exist.
        """
        subpath = ToolManager.TOOL_PATHS.get(name)
        if not subpath:
            raise ValueError(f"Unknown tool or directory name: {name}")

        full_path = ToolManager._install_dir / subpath

        if not full_path.exists():
            raise FileNotFoundError(f"Tool not found. Please run tool --type {name}")

        return str(full_path)