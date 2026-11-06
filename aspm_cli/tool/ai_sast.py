"""Checksum-verified install of the AI SAST binaries (codeassure + context-graph), side by side.

codeassure looks for ``context-graph`` next to its own executable first, so both go in one folder.
The binaries and an ``ai-sast-SHA256SUMS`` file are hosted on the matching aspm-scanner-cli release
(context-graph's own repo is private); set ``AI_SAST_BASE_URL`` to fetch them from somewhere else.
"""
import hashlib
import os
import platform
import shutil
import urllib.request
from pathlib import Path

from aspm_cli.utils.logger import Logger
from aspm_cli.utils.version import get_version

SUMS_NAME = "ai-sast-SHA256SUMS"
TOOLS = ("codeassure", "context-graph")
PLATFORMS = {("Linux", "amd64"): "linux-amd64", ("Darwin", "arm64"): "darwin-arm64", ("Windows", "amd64"): "windows-amd64"}


def _base_url():
    override = (os.getenv("AI_SAST_BASE_URL") or "").strip().rstrip("/")
    return override or f"https://github.com/accuknox/aspm-scanner-cli/releases/download/v{get_version()}"


def _download(url):
    with urllib.request.urlopen(url, timeout=120) as response:  # timeout is per read, so big files still finish
        return response.read()


def _parse_sums(text):
    sums = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            sums[parts[1].lstrip("*")] = parts[0].lower()
    return sums


def install_ai_sast(install_dir, overwrite=False):
    system = platform.system()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    target = PLATFORMS.get((system, arch))
    if not target:
        Logger.get_logger().error(f"AI SAST binaries are not available for {system} {arch} (Linux amd64, macOS arm64, Windows amd64).")
        return False
    suffix = ".exe" if system == "Windows" else ""
    folder = Path(install_dir) / "codeassure"
    destinations = {tool: folder / f"{tool}{suffix}" for tool in TOOLS}
    if not overwrite and all(path.exists() for path in destinations.values()):
        return True
    base = _base_url()
    try:
        sums = _parse_sums(_download(f"{base}/{SUMS_NAME}").decode("utf-8"))
        staged = {}
        for tool in TOOLS:
            name = f"{tool}-{target}{suffix}"
            expected = sums.get(name)
            if not expected:
                raise ValueError(f"{name} is not listed in {SUMS_NAME}")
            data = _download(f"{base}/{name}")
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f"{name} checksum mismatch")
            staged[tool] = data
        folder.mkdir(parents=True, exist_ok=True)
        for tool, data in staged.items():  # only after every file verified, so a bad download never leaves half an install
            temporary = destinations[tool].with_name(destinations[tool].name + ".installing")
            temporary.write_bytes(data)
            temporary.chmod(0o755)
            os.replace(temporary, destinations[tool])
        return True
    except (OSError, ValueError) as exc:
        Logger.get_logger().error(f"AI SAST installation failed: {exc}")
        return False
