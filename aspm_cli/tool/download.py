import os
import sys
import platform
import urllib.request
import tarfile
import tempfile
from pathlib import Path
from aspm_cli.utils.logger import Logger
import shutil

class ToolDownloader:
    TOOL_URLS = {
        "Windows": {
        },
        "Linux": {
            "iac": "https://github.com/safeer-accuknox/use-cases/releases/download/1.0/iac",
            "container": "https://github.com/safeer-accuknox/use-cases/releases/download/1.0/container.tar.gz",
            "secret": "https://github.com/safeer-accuknox/use-cases/releases/download/1.0/secret",
            "sq-sast": "https://github.com/safeer-accuknox/use-cases/releases/download/1.0/sq-sast.tar.gz"
        }
    }

    def __init__(self):
        self.system = platform.system()
        self.is_windows = self.system == "Windows"

        if self.is_windows:
            self.install_dir = Path(os.getenv("USERPROFILE")) / "AppData" / "Local" / "Programs" / "AccuKnox"
        else:
            self.install_dir = Path.home() / ".local" / "bin" / "accuknox"

        self.install_dir.mkdir(parents=True, exist_ok=True)

    def _download_tool(self, tool_type, overwrite=False):
        download_url = self.TOOL_URLS[self.system].get(tool_type)
        if not download_url:
            Logger.get_logger().error(f"No download URL found for {tool_type} on {self.system}")
            return False

        is_tarball = download_url.endswith(".tar.gz")
        ext = ".exe" if self.is_windows and not is_tarball else ""
        destination = (self.install_dir / tool_type).with_suffix(ext)

        # Handle overwrite logic
        if destination.exists() or (is_tarball and (self.install_dir / tool_type).exists()):
            if overwrite:
                Logger.get_logger().debug(f"Overwriting existing {tool_type} at {destination}")
                try:
                    if destination.is_file():
                        destination.unlink()
                    elif destination.is_dir():
                        shutil.rmtree(destination)
                    elif is_tarball and (self.install_dir / tool_type).exists():
                        shutil.rmtree(self.install_dir / tool_type)
                except Exception as e:
                    Logger.get_logger().error(f"Failed to remove existing {tool_type}: {e}")
                    return False
            else:
                Logger.get_logger().info(f"{tool_type} already exists. Skipping download.")
                return False

        Logger.get_logger().debug(f"Downloading {tool_type} from {download_url}")

        if is_tarball:
            with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
                urllib.request.urlretrieve(download_url, tmp.name)
                Logger.get_logger().debug(f"Extracting {tmp.name}")

                with tarfile.open(tmp.name, "r:gz") as tar:
                    members = tar.getmembers()
                    if not members:
                        Logger.get_logger().error(f"Archive {tmp.name} is empty.")
                        return False
                    tar.extractall(path=self.install_dir)
                    Logger.get_logger().debug(f"Extracted to {self.install_dir}")

                os.unlink(tmp.name)
        else:
            urllib.request.urlretrieve(download_url, destination)
            Logger.get_logger().debug(f"Installed {tool_type} at {destination}")

        return True