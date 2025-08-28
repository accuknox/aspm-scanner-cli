import os
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
            # TODO: add Windows tarballs if supported later
        },
        "Linux": {
            "iac": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/iac.tar.gz",
            "container": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/container.tar.gz",
            "secret": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/secret.tar.gz",
            "sq-sast": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/sq-sast.tar.gz",
            "sast": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/sast.tar.gz",
        },
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

        destination = self.install_dir / tool_type

        # Handle overwrite
        if destination.exists():
            if overwrite:
                Logger.get_logger().debug(f"Overwriting existing {tool_type} at {destination}")
                try:
                    if destination.is_dir():
                        shutil.rmtree(destination)
                    else:
                        destination.unlink()
                except Exception as e:
                    Logger.get_logger().error(f"Failed to remove existing {tool_type}: {e}")
                    return False
            else:
                Logger.get_logger().info(f"{tool_type} already exists. Skipping download.")
                return False

        Logger.get_logger().debug(f"Downloading {tool_type} from {download_url}")

        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            urllib.request.urlretrieve(download_url, tmp.name)
            Logger.get_logger().debug(f"Extracting {tmp.name}")

            try:
                with tarfile.open(tmp.name, "r:gz") as tar:
                    members = tar.getmembers()
                    if not members:
                        Logger.get_logger().error(f"Archive {tmp.name} is empty.")
                        return False

                    # Extract directly into install_dir (no subfolder)
                    tar.extractall(path=self.install_dir)

                    Logger.get_logger().debug(f"Extracted {tool_type} to {self.install_dir}")
            except Exception as e:
                Logger.get_logger().error(f"Failed to extract {tool_type}: {e}")
                return False
            finally:
                os.unlink(tmp.name)

        return True