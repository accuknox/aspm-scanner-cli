import os
import sys
import platform
import urllib.request
from pathlib import Path

from aspm_cli.utils.logger import Logger

class ToolDownloader:
    TOOL_URLS = {
        "Windows": {
            "iac": f"https://github.com/accuknox/aspm-scanner-cli/releases/download/iac.exe",
        },
        "Linux": {
            "iac": f"https://github.com/safeer-accuknox/use-cases/releases/download/1.0/checkov",
            "container": f"https://github.com/safeer-accuknox/use-cases/releases/download/1.0/trivy",
        }
    }

    def __init__(self):
        self.system = platform.system()
        self.is_windows = platform.system() == "Windows"

        if self.is_windows:
            self.install_dir = Path(os.getenv("USERPROFILE")) / "AppData" / "Local" / "Programs" / "AccuKnox"
        else:
            self.install_dir = Path.home() / ".local" / "bin" / "accuknox"
        self.install_dir.mkdir(parents=True, exist_ok=True)

    def _download_tool(self, tool_type):
        download_url = self.TOOL_URLS[self.system].get(tool_type)
        if not download_url:
            print(f"❌ No download URL found for {tool_type} on {self.system}")
            return

        ext = ".exe" if self.system == "Windows" else ""
        destination = (self.install_dir / tool_type).with_suffix(ext)

        Logger.get_logger().debug(f"Downloading {tool_type} from {download_url}")
        urllib.request.urlretrieve(download_url, destination)
        if not self.is_windows:
            destination.chmod(0o755)
        Logger.get_logger().debug(f"Installed {tool_type} from {destination}")