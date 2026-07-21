import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from aspm_cli.utils.docker_runtime import cpu_arch, local_tool_install_supported, platform_name
from aspm_cli.utils.logger import Logger


# Keep versions aligned with utils/prepare-aspm-scanners.sh where possible.
# Darwin SAST uses a slightly newer OpenGrep so both arm64 and x86_64 assets exist.
CHECKOV_VERSION = "3.2.458"
TRUFFLEHOG_VERSION = "3.90.3"
TRIVY_VERSION = "0.69.3"
GITLEAKS_VERSION = "8.24.2"
SONAR_SCANNER_VERSION = "7.1.0.4889"
OPENGREP_VERSION_LINUX = "v1.0.0-alpha.14"
OPENGREP_VERSION_DARWIN = "v1.22.0"
OPENGREP_RULES_COMMIT = "f1d2b562b414783763fd02a6ed2736eaed622efa"

# Tools with native macOS installers (Intel x86_64 + Apple Silicon arm64).
DARWIN_SUPPORTED_TOOLS = frozenset({
    "iac",
    "sast",
    "secret",
    "container",
    "gitleaks",
    "sq-sast",
})

# Tools with native Windows installers (x86_64 / amd64).
WINDOWS_SUPPORTED_TOOLS = frozenset({
    "iac",
    "sast",
    "secret",
    "container",
    "gitleaks",
    "sq-sast",
})


class ToolDownloader:
    TOOL_URLS = {
        "Windows": {
            # Windows local install uses upstream vendor binaries (see _install_windows_*).
        },
        "Linux": {
            "iac": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/iac.tar.gz",
            "container": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/container.tar.gz",
            "secret": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/secret.tar.gz",
            "sq-sast": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/sq-sast.tar.gz",
            "sast": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/sast.tar.gz",
            "dast": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.10.1/dast.tar.gz",
            "codeassure": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.14.7-rc.3/codeassure.tar.gz",
            "gitleaks": "https://github.com/accuknox/aspm-scanner-cli/releases/download/v0.14.7-rc.3/gitleaks.tar.gz",
        },
    }

    def __init__(self):
        self.system = platform.system()
        self.is_windows = self.system == "Windows"
        self.is_darwin = self.system == "Darwin"

        if self.is_windows:
            self.install_dir = Path(os.getenv("USERPROFILE")) / "AppData" / "Local" / "Programs" / "AccuKnox"
        else:
            self.install_dir = Path.home() / ".local" / "bin" / "accuknox"

        self.install_dir.mkdir(parents=True, exist_ok=True)

    def download_tool(self, tool_type, overwrite=False):
        if not local_tool_install_supported():
            Logger.get_logger().error(
                f"Local scanner tool install is not supported on {platform_name()}. "
                "Install Docker and run scans with --container-mode."
            )
            return False

        if self.is_windows:
            return self._download_windows_tool(tool_type, overwrite=overwrite)

        if self.is_darwin:
            return self._download_darwin_tool(tool_type, overwrite=overwrite)

        return self._download_linux_tarball(tool_type, overwrite=overwrite)

    def _download_linux_tarball(self, tool_type, overwrite=False):
        download_url = self.TOOL_URLS.get("Linux", {}).get(tool_type)
        if not download_url:
            Logger.get_logger().error(f"No download URL found for {tool_type} on {self.system}")
            return False

        destination = self.install_dir / tool_type
        if not self._prepare_destination(destination, tool_type, overwrite):
            return False

        Logger.get_logger().debug(f"Downloading {tool_type} from {download_url}")
        return self._download_and_extract_tar_gz(download_url, self.install_dir, tool_type)

    def _download_darwin_tool(self, tool_type, overwrite=False):
        if tool_type not in DARWIN_SUPPORTED_TOOLS:
            Logger.get_logger().error(
                f"Local install for '{tool_type}' is not available on macOS yet. "
                f"Supported local tools: {', '.join(sorted(DARWIN_SUPPORTED_TOOLS))}. "
                "Use --container-mode for this scanner, or install Docker Desktop."
            )
            return False

        try:
            arch = cpu_arch()
        except ValueError as e:
            Logger.get_logger().error(str(e))
            return False

        destination = self.install_dir / tool_type
        # sast layout uses a folder named "sast"; sq-sast folder; others are files or folders
        dest_paths = {
            "iac": self.install_dir / "iac",
            "secret": self.install_dir / "secret",
            "container": self.install_dir / "container",
            "gitleaks": self.install_dir / "gitleaks",
            "sast": self.install_dir / "sast",
            "sq-sast": self.install_dir / "sq-sast",
        }
        destination = dest_paths[tool_type]
        if not self._prepare_destination(destination, tool_type, overwrite):
            return False

        installers = {
            "iac": self._install_darwin_iac,
            "sast": self._install_darwin_sast,
            "secret": self._install_darwin_secret,
            "container": self._install_darwin_container,
            "gitleaks": self._install_darwin_gitleaks,
            "sq-sast": self._install_darwin_sq_sast,
        }
        try:
            return installers[tool_type](arch)
        except Exception as e:
            Logger.get_logger().error(f"Failed to install {tool_type} for macOS ({arch}): {e}")
            return False

    def _prepare_destination(self, destination: Path, tool_type: str, overwrite: bool) -> bool:
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
                Logger.get_logger().warning(f"{tool_type} already exists. Skipping download.")
                return True
        return True

    def _download_file(self, url: str, dest: Path):
        Logger.get_logger().debug(f"Downloading {url}")
        urllib.request.urlretrieve(url, dest)

    def _download_and_extract_tar_gz(self, url: str, extract_to: Path, tool_type: str) -> bool:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_name = tmp.name
        try:
            self._download_file(url, Path(tmp_name))
            with tarfile.open(tmp_name, "r:gz") as tar:
                members = tar.getmembers()
                if not members:
                    Logger.get_logger().error(f"Archive for {tool_type} is empty.")
                    return False
                tar.extractall(path=extract_to)
            Logger.get_logger().debug(f"Extracted {tool_type} to {extract_to}")
            return True
        except Exception as e:
            Logger.get_logger().error(f"Failed to extract {tool_type}: {e}")
            return False
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def _chmod_x(self, path: Path):
        path.chmod(path.stat().st_mode | 0o111)

    def _install_darwin_iac(self, arch: str) -> bool:
        """
        Install Checkov as ``iac``.

        Bridgecrew's published ``checkov_darwin_X86_64.zip`` is mislabeled — the binary
        inside is arm64. Use that zip on Apple Silicon. On Intel macOS, install Checkov
        into a dedicated venv via pip (no usable x86_64 standalone zip).
        """
        dest = self.install_dir / "iac"
        venv_dir = self.install_dir / "iac-venv"

        if arch == "x86_64":
            Logger.get_logger().info(
                "Checkov's published Darwin standalone zip is arm64-only; "
                f"installing Checkov {CHECKOV_VERSION} via pip for Intel Mac."
            )
            if venv_dir.exists():
                shutil.rmtree(venv_dir)
            subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
            pip = venv_dir / "bin" / "pip"
            subprocess.run(
                [str(pip), "install", "--upgrade", "pip"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [str(pip), "install", f"checkov=={CHECKOV_VERSION}"],
                check=True,
            )
            checkov_bin = venv_dir / "bin" / "checkov"
            if not checkov_bin.exists():
                raise FileNotFoundError(f"checkov not found after pip install at {checkov_bin}")
            dest.write_text(
                "#!/bin/sh\n"
                f'exec "{checkov_bin}" "$@"\n',
                encoding="utf-8",
            )
            self._chmod_x(dest)
            return True

        # Apple Silicon: use the mislabeled standalone zip (contains arm64 Mach-O).
        zip_name = "checkov_darwin_X86_64.zip"
        Logger.get_logger().info(
            "Installing Checkov Darwin standalone build "
            f"(asset name {zip_name}; binary is arm64)."
        )
        url = (
            f"https://github.com/bridgecrewio/checkov/releases/download/"
            f"{CHECKOV_VERSION}/{zip_name}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / zip_name
            self._download_file(url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)
            src = Path(tmp) / "dist" / "checkov"
            if not src.exists():
                candidates = list(Path(tmp).rglob("checkov"))
                if not candidates:
                    raise FileNotFoundError("checkov binary not found in archive")
                src = candidates[0]
            shutil.copy2(src, dest)
            self._chmod_x(dest)
        return True

    def _install_darwin_sast(self, arch: str) -> bool:
        binary_name = "opengrep_osx_arm64" if arch == "arm64" else "opengrep_osx_x86"
        url = (
            f"https://github.com/opengrep/opengrep/releases/download/"
            f"{OPENGREP_VERSION_DARWIN}/{binary_name}"
        )
        sast_dir = self.install_dir / "sast"
        sast_dir.mkdir(parents=True, exist_ok=True)
        dest = sast_dir / "sast"
        self._download_file(url, dest)
        self._chmod_x(dest)

        rules_url = (
            f"https://api.github.com/repos/opengrep/opengrep-rules/tarball/{OPENGREP_RULES_COMMIT}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / "rules.tar.gz"
            self._download_file(rules_url, tar_path)
            extract_dir = Path(tmp) / "rules_extract"
            extract_dir.mkdir()
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=extract_dir)
            # GitHub API tarball has a top-level repo-commit directory
            children = [p for p in extract_dir.iterdir() if p.is_dir()]
            rules_src = children[0] if children else extract_dir
            for noise in (".pre-commit-config.yaml", "stats", ".github"):
                noise_path = rules_src / noise
                if noise_path.is_dir():
                    shutil.rmtree(noise_path)
                elif noise_path.exists():
                    noise_path.unlink()
            rules_dest = sast_dir / "rules"
            if rules_dest.exists():
                shutil.rmtree(rules_dest)
            shutil.copytree(rules_src, rules_dest)
        return True

    def _install_darwin_secret(self, arch: str) -> bool:
        hog_arch = "arm64" if arch == "arm64" else "amd64"
        tar_name = f"trufflehog_{TRUFFLEHOG_VERSION}_darwin_{hog_arch}.tar.gz"
        url = (
            f"https://github.com/trufflesecurity/trufflehog/releases/download/"
            f"v{TRUFFLEHOG_VERSION}/{tar_name}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / tar_name
            self._download_file(url, tar_path)
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=tmp)
            src = Path(tmp) / "trufflehog"
            dest = self.install_dir / "secret"
            shutil.copy2(src, dest)
            self._chmod_x(dest)
        return True

    def _install_darwin_container(self, arch: str) -> bool:
        # AccuKnox Trivy fork does not publish Darwin builds; use Aqua Trivy at the same version.
        aqua_arch = "ARM64" if arch == "arm64" else "64bit"
        tar_name = f"trivy_{TRIVY_VERSION}_macOS-{aqua_arch}.tar.gz"
        url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{tar_name}"
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / tar_name
            self._download_file(url, tar_path)
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=tmp)
            src = Path(tmp) / "trivy"
            dest = self.install_dir / "container"
            shutil.copy2(src, dest)
            self._chmod_x(dest)
        return True

    def _install_darwin_gitleaks(self, arch: str) -> bool:
        gl_arch = "arm64" if arch == "arm64" else "x64"
        tar_name = f"gitleaks_{GITLEAKS_VERSION}_darwin_{gl_arch}.tar.gz"
        url = (
            f"https://github.com/gitleaks/gitleaks/releases/download/"
            f"v{GITLEAKS_VERSION}/{tar_name}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / tar_name
            self._download_file(url, tar_path)
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=tmp)
            src = Path(tmp) / "gitleaks"
            dest = self.install_dir / "gitleaks"
            shutil.copy2(src, dest)
            self._chmod_x(dest)
        return True

    def _install_darwin_sq_sast(self, arch: str) -> bool:
        sq_arch = "aarch64" if arch == "arm64" else "x64"
        zip_name = f"sonar-scanner-cli-{SONAR_SCANNER_VERSION}-macosx-{sq_arch}.zip"
        url = f"https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/{zip_name}"
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / zip_name
            self._download_file(url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)
            # Prefer extracted dirs only (the zip filename also matches sonar-scanner*).
            extracted = next(
                (p for p in Path(tmp).iterdir() if p.is_dir() and p.name.startswith("sonar-scanner")),
                None,
            )
            if extracted is None:
                raise FileNotFoundError("sonar-scanner directory not found in archive")
            dest = self.install_dir / "sq-sast"
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(extracted, dest)
            # Zip extractions often lose +x; restore execute bits on launcher + JRE.
            for folder in (dest / "bin", dest / "jre" / "bin"):
                if folder.is_dir():
                    for helper in folder.iterdir():
                        if helper.is_file():
                            self._chmod_x(helper)
        return True

    def _download_windows_tool(self, tool_type, overwrite=False):
        if tool_type not in WINDOWS_SUPPORTED_TOOLS:
            Logger.get_logger().error(
                f"Local install for '{tool_type}' is not available on Windows yet. "
                f"Supported local tools: {', '.join(sorted(WINDOWS_SUPPORTED_TOOLS))}. "
                "Use --container-mode for this scanner, or install Docker Desktop."
            )
            return False

        # Prefer checking both extensionless and .exe destinations for overwrite.
        dest_candidates = {
            "iac": [self.install_dir / "iac.exe", self.install_dir / "iac"],
            "secret": [self.install_dir / "secret.exe", self.install_dir / "secret"],
            "container": [self.install_dir / "container.exe", self.install_dir / "container"],
            "gitleaks": [self.install_dir / "gitleaks.exe", self.install_dir / "gitleaks"],
            "sast": [self.install_dir / "sast"],
            "sq-sast": [self.install_dir / "sq-sast"],
        }
        for destination in dest_candidates[tool_type]:
            if destination.exists() and not self._prepare_destination(destination, tool_type, overwrite):
                return False

        installers = {
            "iac": self._install_windows_iac,
            "sast": self._install_windows_sast,
            "secret": self._install_windows_secret,
            "container": self._install_windows_container,
            "gitleaks": self._install_windows_gitleaks,
            "sq-sast": self._install_windows_sq_sast,
        }
        try:
            return installers[tool_type]()
        except Exception as e:
            Logger.get_logger().error(f"Failed to install {tool_type} for Windows: {e}")
            return False

    def _find_extracted_file(self, root: Path, names) -> Path:
        for name in names:
            direct = root / name
            if direct.exists():
                return direct
            matches = list(root.rglob(name))
            if matches:
                return matches[0]
        raise FileNotFoundError(f"Could not find any of {names} under {root}")

    def _install_windows_iac(self) -> bool:
        zip_name = "checkov_windows_X86_64.zip"
        url = (
            f"https://github.com/bridgecrewio/checkov/releases/download/"
            f"{CHECKOV_VERSION}/{zip_name}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / zip_name
            self._download_file(url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)
            src = self._find_extracted_file(Path(tmp), ["checkov.exe", "checkov"])
            dest = self.install_dir / "iac.exe"
            shutil.copy2(src, dest)
        return True

    def _install_windows_sast(self) -> bool:
        url = (
            f"https://github.com/opengrep/opengrep/releases/download/"
            f"{OPENGREP_VERSION_DARWIN}/opengrep_windows_x86.exe"
        )
        sast_dir = self.install_dir / "sast"
        sast_dir.mkdir(parents=True, exist_ok=True)
        dest = sast_dir / "sast.exe"
        self._download_file(url, dest)

        rules_url = (
            f"https://api.github.com/repos/opengrep/opengrep-rules/tarball/{OPENGREP_RULES_COMMIT}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / "rules.tar.gz"
            self._download_file(rules_url, tar_path)
            extract_dir = Path(tmp) / "rules_extract"
            extract_dir.mkdir()
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=extract_dir)
            children = [p for p in extract_dir.iterdir() if p.is_dir()]
            rules_src = children[0] if children else extract_dir
            for noise in (".pre-commit-config.yaml", "stats", ".github"):
                noise_path = rules_src / noise
                if noise_path.is_dir():
                    shutil.rmtree(noise_path)
                elif noise_path.exists():
                    noise_path.unlink()
            rules_dest = sast_dir / "rules"
            if rules_dest.exists():
                shutil.rmtree(rules_dest)
            shutil.copytree(rules_src, rules_dest)
        return True

    def _install_windows_secret(self) -> bool:
        tar_name = f"trufflehog_{TRUFFLEHOG_VERSION}_windows_amd64.tar.gz"
        url = (
            f"https://github.com/trufflesecurity/trufflehog/releases/download/"
            f"v{TRUFFLEHOG_VERSION}/{tar_name}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            tar_path = Path(tmp) / tar_name
            self._download_file(url, tar_path)
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=tmp)
            src = self._find_extracted_file(Path(tmp), ["trufflehog.exe", "trufflehog"])
            dest = self.install_dir / "secret.exe"
            shutil.copy2(src, dest)
        return True

    def _install_windows_container(self) -> bool:
        zip_name = f"trivy_{TRIVY_VERSION}_windows-64bit.zip"
        url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{zip_name}"
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / zip_name
            self._download_file(url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)
            src = self._find_extracted_file(Path(tmp), ["trivy.exe", "trivy"])
            dest = self.install_dir / "container.exe"
            shutil.copy2(src, dest)
        return True

    def _install_windows_gitleaks(self) -> bool:
        zip_name = f"gitleaks_{GITLEAKS_VERSION}_windows_x64.zip"
        url = (
            f"https://github.com/gitleaks/gitleaks/releases/download/"
            f"v{GITLEAKS_VERSION}/{zip_name}"
        )
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / zip_name
            self._download_file(url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)
            src = self._find_extracted_file(Path(tmp), ["gitleaks.exe", "gitleaks"])
            dest = self.install_dir / "gitleaks.exe"
            shutil.copy2(src, dest)
        return True

    def _install_windows_sq_sast(self) -> bool:
        zip_name = f"sonar-scanner-cli-{SONAR_SCANNER_VERSION}-windows-x64.zip"
        url = f"https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/{zip_name}"
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / zip_name
            self._download_file(url, zip_path)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp)
            extracted = next(
                (p for p in Path(tmp).iterdir() if p.is_dir() and p.name.startswith("sonar-scanner")),
                None,
            )
            if extracted is None:
                raise FileNotFoundError("sonar-scanner directory not found in archive")
            dest = self.install_dir / "sq-sast"
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(extracted, dest)
        return True
