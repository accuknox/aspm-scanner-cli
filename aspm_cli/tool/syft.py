"""Pinned, checksum-verified Syft installation for native artifact scans."""
import hashlib
import os
import platform
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from aspm_cli.utils.logger import Logger

VERSION = "1.42.3"
CHECKSUMS = {
    ("Linux", "amd64"): "0d6be741479eddd2c8644a288990c04f3df0d609bbc1599a005532a9dff63509",
    ("Linux", "arm64"): "dc630590c953347789d08f8ebf57c7d8094db89100785fcd94b1cddeac791804",
    ("Darwin", "amd64"): "c00d01b7c43504708c8922d643d1cbaefa62ca8876baa4d2c2cf4c3be43707a9",
    ("Darwin", "arm64"): "d71ee7db2be0fe2e96f679fd9d69ef04274cc86c8604707797080a21070b3f32",
    ("Windows", "amd64"): "e1b9f4945aa64c2b34970bec617623d7f803d0661b48a50b966768b363322e2d",
    ("Windows", "arm64"): "76db35f9ec13628e8465685e9773e7de4f57efe1f05bb99959fdde59bdef5f6a",
}


def install_syft(install_dir, overwrite=False):
    system = platform.system()
    arch = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
    expected = CHECKSUMS.get((system, arch))
    if not expected:
        Logger.get_logger().error("Syft is unavailable for this platform/architecture.")
        return False
    executable = "syft.exe" if system == "Windows" else "syft"
    destination = Path(install_dir) / executable
    if destination.exists() and not overwrite:
        return True
    suffix = "zip" if system == "Windows" else "tar.gz"
    name = f"syft_{VERSION}_{system.lower()}_{arch}.{suffix}"
    try:
        with tempfile.TemporaryDirectory() as work:
            archive_path = Path(work) / name
            with urllib.request.urlopen(f"https://github.com/anchore/syft/releases/download/v{VERSION}/{name}", timeout=120) as response, archive_path.open("wb") as output:
                shutil.copyfileobj(response, output)
            if hashlib.sha256(archive_path.read_bytes()).hexdigest() != expected:
                raise ValueError("Syft download checksum mismatch")
            staged = Path(work) / executable
            if suffix == "zip":
                with zipfile.ZipFile(archive_path) as archive, archive.open(executable) as source, staged.open("wb") as output:
                    shutil.copyfileobj(source, output)
            else:
                with tarfile.open(archive_path) as archive:
                    member = archive.getmember(executable)
                    if not member.isfile():
                        raise ValueError("Invalid Syft executable")
                    with archive.extractfile(member) as source, staged.open("wb") as output:
                        shutil.copyfileobj(source, output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix(".installing")
            shutil.copyfile(staged, temporary)
            temporary.chmod(0o755)
            os.replace(temporary, destination)
        return True
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as exc:
        Logger.get_logger().error(f"Syft installation failed: {exc}")
        return False
