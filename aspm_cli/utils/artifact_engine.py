"""Portable artifact scanner, vendored identically in the CLI and backend.

No application imports: both callers use this contract with their own tool executor.
Sync with scripts/sync-artifact-engine.py after editing this file.
"""
import bz2
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = 1
TARGET_TYPES = ("auto", "directory", "manifest", "binary", "archive", "sbom")
MANIFEST_NAMES = frozenset({
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock", "pyproject.toml", "pom.xml", "go.mod",
    "go.sum", "Cargo.lock", "Cargo.toml", "Gemfile.lock", "composer.lock", "packages.lock.json",
    "packages.config", "pubspec.lock", "mix.lock", "Package.resolved",
})
MAX_BYTES = 512 * 1024**2
MAX_EXPANDED = 2 * 1024**3
MAX_MEMBERS = 100000
# Local (CLI) scans never upload the artifact, so they may be larger than a backend upload.
LOCAL_MAX_BYTES = 4 * 1024**3
LOCAL_MAX_EXPANDED = 16 * 1024**3
MAX_NEST_DEPTH = 3
MAX_NOTES = 10
# Package archives Syft/Trivy read directly; unpacking them would hide their metadata.
NATIVE_ARCHIVE_SUFFIXES = frozenset({".jar", ".war", ".ear", ".par", ".rpm", ".deb"})
# Office/e-book zips carry no dependency metadata, so nested unpacking skips them.
DOCUMENT_SUFFIXES = frozenset({".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub"})
IMAGE_FORMATS = frozenset({"docker-archive", "oci-archive", "oci-layout"})
SYFT_IMAGE_SCHEMES = {"docker-archive": "docker-archive", "oci-archive": "oci-archive", "oci-layout": "oci-dir"}
COMPRESSED_FORMATS = frozenset({"gzip", "xz", "bzip2"})
EXTERNAL_FORMATS = frozenset({"7z", "rar"})


class ArtifactError(ValueError):
    pass


class Limits:
    """One expansion budget shared by every (nested) extraction of a single scan."""

    def __init__(self, max_bytes=None, max_expanded=None, max_members=None):
        # Resolved at construction so tests and callers can patch the module constants.
        self.max_bytes = MAX_BYTES if max_bytes is None else max_bytes
        self.max_expanded = MAX_EXPANDED if max_expanded is None else max_expanded
        self.max_members = MAX_MEMBERS if max_members is None else max_members
        self.members = 0
        self.expanded = 0

    def exceeded(self, size=0, members=0):
        return self.members + members > self.max_members or self.expanded + size > self.max_expanded

    def take(self, size, members=1):
        if self.exceeded(size, members):
            raise ArtifactError("Archive exceeds expansion limits.")
        self.members += members
        self.expanded += size


def read_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def sbom_format(document):
    if not isinstance(document, dict):
        return None
    if document.get("bomFormat") == "CycloneDX" and isinstance(document.get("components", []), list):
        return "cyclonedx"
    if str(document.get("spdxVersion", "")).startswith("SPDX-") and isinstance(document.get("packages", []), list):
        return "spdx"
    return None


def _read_magic(path, size=16):
    with Path(path).open("rb") as stream:
        return stream.read(size)


def _compression(magic):
    if magic[:2] == b"\x1f\x8b":
        return "gzip"
    if magic[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if magic[:3] == b"BZh":
        return "bzip2"
    return None


def _docker_manifest(raw):
    try:
        data = json.loads(raw)
    except ValueError:
        return False
    return isinstance(data, list) and bool(data) and all(
        isinstance(item, dict) and "Config" in item and "Layers" in item for item in data)


def image_format(path):
    """Return docker-archive or oci-archive for a container image tarball, else None.

    Only tar headers (and a small manifest.json) are read; nothing is extracted.
    """
    try:
        with tarfile.open(path) as archive:
            names = set()
            for count, member in enumerate(archive):
                if count > MAX_MEMBERS:
                    break
                name = member.name[2:] if member.name.startswith("./") else member.name
                if name == "manifest.json" and member.isfile() and member.size <= 1024 * 1024:
                    handle = archive.extractfile(member)
                    if handle is not None and _docker_manifest(handle.read()):
                        return "docker-archive"
                names.add(name)
            if {"oci-layout", "index.json"} <= names:
                return "oci-archive"
    except (tarfile.TarError, OSError, EOFError, lzma.LZMAError):
        return None
    return None


def detect_format(path):
    """Finer-grained input description used to choose tooling (never raises for unknown data)."""
    path = Path(path)
    if path.is_dir():
        return "oci-layout" if (path / "oci-layout").is_file() and (path / "index.json").is_file() else "directory"
    try:
        magic = _read_magic(path)
        if magic[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7z"
        if magic[:6] == b"Rar!\x1a\x07":
            return "rar"
        compression = _compression(magic)
        if tarfile.is_tarfile(path):
            return image_format(path) or "tar"
        if compression:
            return compression
        if zipfile.is_zipfile(path):
            return "zip"
    except (OSError, EOFError, lzma.LZMAError):
        pass
    return "file"


def _is_android_package(path):
    try:
        with zipfile.ZipFile(path) as archive:
            return "AndroidManifest.xml" in archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return False


def _archive_like(path, suffix):
    try:
        return (zipfile.is_zipfile(path) or tarfile.is_tarfile(path) or suffix in {".rpm", ".deb"}
                or detect_format(path) in EXTERNAL_FORMATS | COMPRESSED_FORMATS)
    except (EOFError, zlib.error, lzma.LZMAError, gzip.BadGzipFile) as exc:
        raise ArtifactError("Archive is corrupt or unsupported.") from exc


def detect_target(path, requested="auto", max_bytes=None):
    path = Path(path)
    limit = MAX_BYTES if max_bytes is None else max_bytes
    if path.is_symlink():
        raise ArtifactError("Symbolic links are unsupported.")
    if requested not in TARGET_TYPES:
        raise ArtifactError("Unsupported target type.")
    if not path.exists() or path.is_symlink():
        raise ArtifactError("Target must exist and cannot be a symbolic link.")
    if path.is_dir():
        # An OCI image layout directory is an image, not a source tree.
        detected = "archive" if detect_format(path) == "oci-layout" else "directory"
    elif not path.is_file():
        raise ArtifactError("Target must be a regular file or directory.")
    else:
        if path.stat().st_size > limit:
            raise ArtifactError(f"Artifact exceeds the {limit // 1024**2} MiB size limit.")
        magic = _read_magic(path, 4)
        suffix = path.suffix.lower()
        # Alpine .apk packages are tar archives; only Android packages belong to the mobile scanner.
        if suffix == ".ipa" or (suffix == ".apk" and _is_android_package(path)):
            raise ArtifactError("Use the mobile scanner for APK and IPA inputs.")
        try:
            doc = read_json(path) if path.suffix.lower() == ".json" else None
        except (UnicodeError, ValueError):
            doc = None
        if sbom_format(doc):
            detected = "sbom"
        elif path.name in MANIFEST_NAMES or path.name.endswith((".deps.json", "gradle.lockfile", ".sbt.lock", "Packages.props")):
            detected = "manifest"
        elif magic == b"\x7fELF" or magic[:2] == b"MZ" or magic in {
            b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
        }:
            detected = "binary"
        elif _archive_like(path, suffix):
            detected = "archive"
        else:
            raise ArtifactError("Unsupported input. Supply a supported manifest, SBOM, executable, or package archive.")
    if requested != "auto" and requested != detected:
        raise ArtifactError(f"Target is {detected}, not {requested}.")
    return detected


def fingerprint(path, max_expanded=None):
    path = Path(path)
    expanded_limit = MAX_EXPANDED if max_expanded is None else max_expanded
    digest = hashlib.sha256()
    total = 0
    files = sorted(path.rglob("*")) if path.is_dir() else [path]
    count = 0
    for file in files:
        if path.is_dir() and ".git" in file.relative_to(path).parts:
            continue
        if file.is_symlink():
            raise ArtifactError("Symbolic links are unsupported in artifact bundles.")
        if file.is_dir():
            continue
        if not file.is_file():
            raise ArtifactError("Artifact bundles may contain only regular files.")
        count += 1
        if count > MAX_MEMBERS:
            raise ArtifactError("Artifact contains too many files.")
        if path.is_dir():
            digest.update(str(file.relative_to(path)).replace(os.sep, "/").encode() + b"\0")
        with file.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > expanded_limit:
                    raise ArtifactError("Artifact exceeds the expanded size limit.")
                digest.update(block)
        if path.is_dir():
            digest.update(b"\0")
    return digest.hexdigest(), total


def safe_member(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name or "\0" in name:
        raise ArtifactError("Unsafe archive path.")
    return path


def extract_archive(path, destination, limits=None):
    """Validate every member before extraction; never restore permissions or links.

    Every failure mode is an ArtifactError so callers (the CLI and the backend's upload
    validation) can report it instead of crashing on a library exception.
    """
    limits = limits or Limits()
    try:
        if not zipfile.is_zipfile(path) and not tarfile.is_tarfile(path):
            if detect_format(path) in EXTERNAL_FORMATS:
                return extract_external(path, destination, limits)
            raise ArtifactError("Unsupported archive type; use a zip, tar, 7z or rar archive.")
        return _extract_zip_or_tar(path, destination, limits)
    except (tarfile.TarError, zipfile.BadZipFile, gzip.BadGzipFile, EOFError, zlib.error, lzma.LZMAError) as exc:
        raise ArtifactError("Archive is corrupt or unsupported.") from exc


def _extract_zip_or_tar(path, destination, limits):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    names = set()
    def check(name, size):
        member = safe_member(name)
        key = str(member).casefold()
        if key in names:
            raise ArtifactError("Duplicate archive path.")
        names.add(key)
        limits.take(size)
        return destination.joinpath(*member.parts)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            members = []
            for item in archive.infolist():
                target = check(item.orig_filename, item.file_size)  # raw name: zipfile rewrites "\\" to "/" on Windows
                if stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1:
                    raise ArtifactError("Encrypted archives and symbolic links are unsupported.")
                members.append((item, target))
            for item, target in members:
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(item) as source, target.open("xb") as output:
                        copy_bounded(source, output, item.file_size)
    else:
        with tarfile.open(path) as archive:
            members = []
            for item in archive:
                target = check(item.name, item.size)
                if not item.isdir() and not item.isfile():
                    raise ArtifactError("Archive links and special files are unsupported.")
                members.append((item, target))
            for item, target in members:
                if item.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(item) as source, target.open("xb") as output:
                        copy_bounded(source, output, item.size)
    return destination


def copy_bounded(source, output, limit):
    size = 0
    while True:
        block = source.read(min(1024 * 1024, limit - size + 1))
        if not block:
            break
        size += len(block)
        if size > limit:
            raise ArtifactError("Archive member exceeds its declared size.")
        output.write(block)


_DECOMPRESSORS = {"gzip": gzip.open, "xz": lzma.open, "bzip2": bz2.open}


def decompress_file(path, destination, compression, limits):
    """Stream a single compressed file to ``destination`` under the shared expansion budget."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with _DECOMPRESSORS[compression](path, "rb") as source, destination.open("xb") as output:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                limits.take(len(block), 0)
                output.write(block)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        raise ArtifactError("Compressed file is corrupt or unreadable.") from exc
    return destination


def _find_extractor():
    """7-Zip is preferred (explicit sizes/links in its listing); libarchive's bsdtar is the fallback."""
    for name in ("7zz", "7z", "7za", "bsdtar"):
        found = shutil.which(name)
        if found:
            return ("bsdtar" if name == "bsdtar" else "7z"), found
    raise ArtifactError("7z and rar archives need an external extractor. Install 7-Zip (7zz/7z) or libarchive "
                        "(bsdtar), or unpack the archive first and scan the directory.")


def _run_extractor(command, timeout=1200):
    try:
        return subprocess.run(command, check=True, timeout=timeout, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ArtifactError("Archive could not be listed or extracted (corrupt, encrypted or unsupported).") from exc


def _windows_names(name):
    return name.replace("\\", "/") if os.name == "nt" else name


def parse_7z_listing(text):
    """Parse ``7z l -slt -ba`` into [(name, size, is_dir)], rejecting links, devices and encryption."""
    entries = []
    for block in re.split(r"\r?\n\r?\n", text.strip()):
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition(" = ")
            if sep and key not in fields:
                fields[key.strip()] = value
        if "Path" not in fields:
            continue
        attributes = fields.get("Attributes", "").split()
        unix_mode = attributes[-1] if attributes else ""
        if fields.get("Encrypted") == "+":
            raise ArtifactError("Encrypted archives and symbolic links are unsupported.")
        if (fields.get("Symbolic Link") or fields.get("Hard Link") or unix_mode[:1] in {"l", "c", "b", "p", "s"}
                or "Link" in " ".join(fields)):
            raise ArtifactError("Archive links and special files are unsupported.")
        is_dir = fields.get("Folder") == "+" or unix_mode[:1] == "d"
        try:
            size = 0 if is_dir else int(fields.get("Size") or 0)
        except ValueError:
            raise ArtifactError("Archive listing is not understood.") from None
        entries.append((_windows_names(fields["Path"]), size, is_dir))
    return entries


_BSDTAR_LINE = re.compile(
    r"^([-dlhcbps])\S{9}[ +@.]?\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(?:\w{3}\s+\d+|\d+\s+\w{3})\s+(?:\d{2}:\d{2}|\d{4})\s(.*)$")


def parse_bsdtar_listing(text):
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _BSDTAR_LINE.match(line)
        if not match:
            raise ArtifactError("Archive listing is not understood; refusing to extract it.")
        kind, size, name = match.group(1), int(match.group(2)), match.group(3)
        if kind not in {"-", "d"}:
            raise ArtifactError("Archive links and special files are unsupported.")
        entries.append((name, 0 if kind == "d" else size, kind == "d"))
    return entries


def _verify_extracted_tree(destination, limits):
    """Independent of the extractor's own safety: no links, no special files, bounded size."""
    for directory, dirnames, filenames in os.walk(destination, followlinks=False):
        for name in [*dirnames, *filenames]:
            info = os.lstat(os.path.join(directory, name))
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ArtifactError("Archive links and special files are unsupported.")
            if stat.S_ISREG(info.st_mode):
                limits.take(info.st_size)


def extract_external(path, destination, limits):
    """Unpack 7z/rar with an external tool after validating its listing with the same rules as zip/tar."""
    flavour, tool = _find_extractor()
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ArtifactError("Extraction directory is not empty.")
    if flavour == "7z":
        listing = _run_extractor([tool, "l", "-slt", "-ba", "--", str(path)]).stdout.decode("utf-8", "replace")
        entries = parse_7z_listing(listing)
    else:
        listing = _run_extractor([tool, "-tvf", str(path)]).stdout.decode("utf-8", "replace")
        entries = parse_bsdtar_listing(listing)
    names = set()
    total = 0
    for name, size, _ in entries:
        key = str(safe_member(name)).casefold()
        if key in names:
            raise ArtifactError("Duplicate archive path.")
        names.add(key)
        total += size
    if limits.exceeded(total, len(entries)):
        raise ArtifactError("Archive exceeds expansion limits.")
    destination.mkdir(parents=True, exist_ok=True)
    try:
        if flavour == "7z":
            _run_extractor([tool, "x", "-y", f"-o{destination}", "--", str(path)])
        else:
            _run_extractor([tool, "-xf", str(path), "-C", str(destination), "--no-same-owner", "--no-same-permissions"])
        _verify_extracted_tree(destination, limits)
    except ArtifactError:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    limits.take(0, len(entries))
    return destination


def extract_any(path, fmt, destination, limits):
    if fmt in EXTERNAL_FORMATS:
        return extract_external(path, destination, limits)
    return extract_archive(path, destination, limits)


def _nested_archive_format(file):
    """Cheap signature test so walking a large tree does not open every file in full."""
    if file.suffix.lower() in NATIVE_ARCHIVE_SUFFIXES | DOCUMENT_SUFFIXES:
        return None
    try:
        header = _read_magic(file, 512)
        if header[:4] == b"PK\x03\x04":
            return "zip" if zipfile.is_zipfile(file) else None
        if header[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7z"
        if header[:6] == b"Rar!\x1a\x07":
            return "rar"
        if header[257:262] == b"ustar" or _compression(header):
            return "tar" if tarfile.is_tarfile(file) else None
    except (OSError, EOFError, lzma.LZMAError):
        pass
    return None


def extract_nested(root, limits, notes, depth=1):
    """Unpack archives found inside an *already extracted* tree (never inside the user's own files).

    Each archive is replaced by ``<name>.extracted`` so its members are inventoried once.
    """
    found = []
    for directory, _, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            file = Path(directory) / name
            fmt = _nested_archive_format(file)
            if fmt:
                found.append((file, fmt))
    if found and depth > MAX_NEST_DEPTH:
        notes.append(f"Archives nested deeper than {MAX_NEST_DEPTH} levels were not unpacked.")
        return
    for file, fmt in found:
        destination = file.with_name(file.name + ".extracted")
        try:
            extract_any(file, fmt, destination, limits)
        except ArtifactError as exc:
            shutil.rmtree(destination, ignore_errors=True)
            notes.append(f"Nested archive {file.relative_to(root)} was not unpacked: {exc}")
            continue
        file.unlink()
        extract_nested(destination, limits, notes, depth + 1)


_EXECUTABLE_MAGICS = {b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                      b"\xca\xfe\xba\xbe", b"\xbf\xba\xfe\xca"}


def _looks_executable(file):
    try:
        head = _read_magic(file, 4)
    except OSError:
        return False
    return head in _EXECUTABLE_MAGICS or head[:2] == b"MZ"


def mark_executables(root):
    """Trivy's binary analyzers skip files without the execute bit, but extraction never restores modes.

    Only files we created inside the private output directory are touched, and nothing is ever run.
    """
    if os.name == "nt":
        return
    root = Path(root)
    files = [root] if root.is_file() else (Path(d) / n for d, _, names in os.walk(root, followlinks=False) for n in names)
    for file in files:
        if not file.is_symlink() and _looks_executable(file):
            os.chmod(file, 0o700)


def stage_executable(path, output):
    """Copy a user's non-executable binary into the output directory so Trivy will analyze it."""
    staged = output / "staged" / path.name
    staged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, staged)
    os.chmod(staged, 0o700)
    return staged


def _decompressed_name(path):
    return path.stem if path.suffix else path.name + ".out"


def prepare_scan_input(path, kind, fmt, output, limits, _depth=0):
    """Return (scan_path, scan_kind, image_format, notes); user input is only ever read.

    ``scan_kind`` is what the scan tooling sees: an extracted tree is a ``directory`` and a
    decompressed payload is re-detected, while ``kind`` stays the artifact's type in the report.
    """
    notes = []
    if kind == "binary" and os.name != "nt" and not os.access(path, os.X_OK):
        path = stage_executable(path, output)
    if kind != "archive":
        return path, kind, None, notes
    if fmt == "oci-layout":
        return path, kind, fmt, notes
    if fmt in {"docker-archive", "oci-archive"}:
        compression = _compression(_read_magic(path))
        if compression:  # trivy/syft expect a plain tar
            path = decompress_file(path, output / "image.tar", compression, limits)
        return path, kind, fmt, notes
    if path.suffix.lower() in NATIVE_ARCHIVE_SUFFIXES:
        return path, kind, None, notes
    if fmt in COMPRESSED_FORMATS:
        if _depth >= MAX_NEST_DEPTH:
            raise ArtifactError(f"Compressed files nested deeper than {MAX_NEST_DEPTH} levels are unsupported.")
        inner = decompress_file(path, output / "decompressed" / _decompressed_name(path), fmt, limits)
        mark_executables(inner)
        # Re-detect: the payload may be a binary, a tar, a zip or another compressed layer.
        return prepare_scan_input(inner, detect_target(inner, "auto", limits.max_expanded),
                                  detect_format(inner), output, limits, _depth + 1)
    root = output / "contents"
    extract_any(path, fmt, root, limits)
    extract_nested(root, limits, notes)
    mark_executables(root)
    return root, "directory", None, notes


def native_executor(tool, args, workdir):
    try:
        subprocess.run([tool, *args], cwd=workdir, check=True, timeout=1200,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except (OSError, subprocess.SubprocessError) as exc:
        diagnostic = Path(workdir) / f"{Path(tool).name}.log"
        stderr = getattr(exc, "stderr", None)
        diagnostic.write_bytes(stderr[-65536:] if isinstance(stderr, bytes) else str(exc).encode()[-65536:])
        raise ArtifactError(f"Scanner failed. Check installation/databases and {diagnostic}.") from exc


def trivy_passes(scan_kind, scan_path, image, bom_path):
    """Ordered (name, trivy args). ``sbom`` always comes first; native passes are merged ahead of it.

    ``trivy fs`` reads lockfiles but has no binary analyzers; ``trivy rootfs`` reads binaries,
    jars and OS packages but not lockfiles, so a tree needs both.
    """
    common = ["--scanners", "vuln", "--list-all-pkgs"]
    inventory = ("sbom", ["sbom", str(bom_path)])
    if image:
        return [inventory, ("image", ["image", "--input", str(scan_path), *common])]
    if scan_kind == "sbom":
        return [inventory]
    if scan_kind == "manifest":
        return [("fs", ["fs", str(scan_path), "--skip-dirs", ".git", *common])]
    if Path(scan_path).is_dir():
        return [inventory,
                ("fs", ["fs", str(scan_path), "--skip-dirs", ".git", *common]),
                ("rootfs", ["rootfs", str(scan_path), "--skip-dirs", ".git", *common])]
    return [inventory, ("rootfs", ["rootfs", str(scan_path), *common])]


def _version_key(version):
    """Syft reports Go modules as 1.2.3 and Trivy as v1.2.3; they are the same release."""
    text = str(version or "").strip().lower()
    return text[1:] if re.match(r"v\d", text) else text


def merge_trivy_reports(reports):
    """Union Trivy reports (highest priority first), keeping one record per advisory/package/version."""
    base = next((r for r in reports if r.get("ArtifactType") == "cyclonedx"), reports[0])
    merged = {key: value for key, value in base.items() if key != "Results"}
    merged["Results"] = []
    seen, seen_targets = set(), set()
    for report in reports:
        for entry in report.get("Results") or []:
            kept = []
            for vuln in entry.get("Vulnerabilities") or []:
                key = (vuln["VulnerabilityID"], vuln["PkgName"], _version_key(vuln.get("InstalledVersion")))
                if key not in seen:
                    seen.add(key)
                    kept.append(vuln)
            target = (entry.get("Target"), entry.get("Type"))
            if not kept and (not entry.get("Packages") or target in seen_targets):
                continue
            seen_targets.add(target)
            item = {k: v for k, v in entry.items() if k != "Vulnerabilities"}
            if kept:
                item["Vulnerabilities"] = kept
            merged["Results"].append(item)
    return merged


def append_missing_components(bom, report):
    """Add a component for every vulnerable package whose exact purl the inventory lacks.

    The backend maps findings to SBOM components by purl (qualifiers included), so a package that
    Trivy reports under a different purl than Syft would otherwise be an unmapped finding.
    """
    components = bom.setdefault("components", [])
    known = {c.get("purl") for c in components if isinstance(c, dict)}
    refs = {c.get("bom-ref") for c in components if isinstance(c, dict)}
    added = []
    for entry in report.get("Results") or []:
        for vuln in entry.get("Vulnerabilities") or []:
            purl = (vuln.get("PkgIdentifier") or {}).get("PURL")
            version = vuln.get("InstalledVersion")
            if not purl or not version or purl in known:
                continue
            ref = f"trivy:{purl}"
            known.add(purl)
            if ref in refs:
                continue
            refs.add(ref)
            components.append({"type": "library", "bom-ref": ref, "name": vuln["PkgName"], "version": version,
                               "purl": purl, "properties": [{"name": "accuknox:inventory:source", "value": "trivy"}]})
            added.append(ref)
    if added:
        dependencies = bom.setdefault("dependencies", [])
        have = {d.get("ref") for d in dependencies if isinstance(d, dict)}
        dependencies.extend({"ref": ref, "dependsOn": []} for ref in added if ref not in have)
        root = (bom.get("metadata") or {}).get("component", {}).get("bom-ref")
        if root:
            edge = next((d for d in dependencies if d.get("ref") == root), None)
            if edge is None:
                edge = {"ref": root, "dependsOn": []}
                dependencies.append(edge)
            edge["dependsOn"] = sorted(set(edge.get("dependsOn") or []) | set(added))
    return len(added)


def _contains_binaries(root, cap=20000):
    """True when the tree holds executables (ELF/PE/Mach-O); bounded so huge trees stay cheap."""
    magics = {b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
    seen = 0
    for directory, _, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            seen += 1
            if seen > cap:
                return False
            try:
                head = _read_magic(Path(directory) / name, 4)
            except OSError:
                continue
            if head in magics or head[:2] == b"MZ":
                return True
    return False


def scan_artifact(target, output_dir, target_type="auto", asset_name=None, project_name=None,
                  syft="syft", trivy="trivy", sbom_only=False, execute=native_executor, on_stage=None,
                  max_bytes=None, max_expanded=None):
    """Return a versioned, portable result envelope; inputs are never rewritten."""
    limits = Limits(max_bytes, max_expanded)
    path = Path(target).resolve()
    kind = detect_target(target, target_type, limits.max_bytes)
    sha256, size = fingerprint(path, limits.max_expanded)
    output = Path(output_dir).resolve()
    # Output must not be inside a directory being scanned.
    if path.is_dir() and (output == path or path in output.parents):
        raise ArtifactError("The result directory must be outside the scan target.")
    output.mkdir(parents=True, exist_ok=True)
    artifact = {"filename": path.name, "name": asset_name or path.name, "type": kind,
                "sha256": sha256, "size": size, "project_name": project_name or ""}
    fmt = detect_format(path) if kind in {"archive", "directory"} else kind
    if kind == "archive":
        artifact["format"] = fmt
    result = {"schema_version": SCHEMA_VERSION, "artifact": artifact, "stages": {},
              "coverage": "limited", "coverage_reasons": [], "sbom": None,
              "vulnerability_report": None, "finding_counts": {}}
    def stage(name, operation):
        result["stages"][name] = {"status": "running"}
        if on_stage:
            on_stage(result["stages"])
        try:
            value = operation()
            result["stages"][name] = {"status": "completed"}
            return value
        except (ArtifactError, OSError, ValueError) as exc:
            result["stages"][name] = {"status": "failed", "message": str(exc)}
            result["coverage_reasons"].append(str(exc))
            return None
        finally:
            if on_stage:
                on_stage(result["stages"])
    # Package archives (jar/rpm/deb) and container images are read natively; general bundles,
    # 7z/rar and compressed files are unpacked (safely, bounded, nested) into the output directory.
    scan_path, scan_kind, image, notes = prepare_scan_input(path, kind, fmt, output, limits)
    if len(notes) > MAX_NOTES:  # e.g. every layer of a nested image tarball; keep the report readable
        notes = notes[:MAX_NOTES] + [f"{len(notes) - MAX_NOTES} more nested archives were not unpacked."]
    result["coverage_reasons"].extend(notes)
    bom_path = output / "sbom.json"
    def inventory():
        if scan_kind == "sbom":
            execute(syft, ["convert", str(path), "-o", f"cyclonedx-json={bom_path}"], output)
        elif image:
            execute(syft, ["scan", f"{SYFT_IMAGE_SCHEMES[image]}:{scan_path}",
                           "-o", f"cyclonedx-json={bom_path}", "--quiet"], output)
        else:
            source = f"{'dir' if scan_path.is_dir() else 'file'}:{scan_path}"
            execute(syft, ["scan", source, "-o", f"cyclonedx-json={bom_path}", "--quiet"], output)
        bom = read_json(bom_path)
        if sbom_format(bom) != "cyclonedx":
            raise ArtifactError("Scanner returned an invalid CycloneDX document.")
        if not isinstance(bom.get("metadata", {}), dict) or not isinstance(bom.get("metadata", {}).get("component", {}), dict):
            raise ArtifactError("Invalid CycloneDX root metadata.")
        bom["project_name"] = project_name or artifact["name"]
        bom["project_classifier"] = "application"
        root = bom.setdefault("metadata", {}).setdefault("component", {})
        root.update({"type": "application", "name": artifact["name"], "version": sha256[:12],
                     "hashes": [{"alg": "SHA-256", "content": sha256}]})
        bom_path.write_text(json.dumps(bom), encoding="utf-8")
        return bom
    result["sbom"] = stage("inventory", inventory)
    if not sbom_only:
        def vulnerabilities():
            reports, failures = [], []
            for name, args in trivy_passes(scan_kind, scan_path, image, bom_path):
                report_path = output / f"vulnerabilities-{name}.json"
                try:
                    if name == "sbom" and not result["sbom"]:
                        raise ArtifactError("Vulnerability scanning requires a successful inventory.")
                    execute(trivy, [*args, "--format", "json", "--output", str(report_path),
                                    "--exit-code", "0", "--quiet"], output)
                    report = read_json(report_path)
                    validate_trivy(report)
                except (ArtifactError, OSError, ValueError) as exc:
                    failures.append((name, str(exc)))
                    continue
                reports.append((name, report))
            if not reports:
                raise ArtifactError(failures[0][1] if len(failures) == 1 else
                                    "All vulnerability scans failed: " + "; ".join(f"{n}: {m}" for n, m in failures))
            result["coverage_reasons"].extend(f"The {name} vulnerability scan failed: {message}" for name, message in failures)
            by_name = dict(reports)
            # On a tie keep the inventory-derived record: its purl is the SBOM component's own purl,
            # so the backend can map it. Native-only findings get a component appended afterwards.
            ordered = ([by_name["sbom"]] if "sbom" in by_name else []) + [r for n, r in reports if n != "sbom"]
            report = merge_trivy_reports(ordered)
            if ("rootfs" in by_name and scan_path.is_dir() and not any(
                    entry.get("Packages") for entry in by_name["rootfs"].get("Results") or [])
                    and _contains_binaries(scan_path)):
                result["coverage_reasons"].append(
                    "The tree contains executables, but no binary analyzer identified embedded packages (files without the execute bit are skipped by Trivy).")
            (output / "vulnerabilities.json").write_text(json.dumps(report), encoding="utf-8")
            return report
        result["vulnerability_report"] = stage("vulnerabilities", vulnerabilities)
        for entry in (result["vulnerability_report"] or {}).get("Results") or []:
            for vuln in entry.get("Vulnerabilities") or []:
                severity = str(vuln.get("Severity", "UNKNOWN")).upper()
                result["finding_counts"][severity] = result["finding_counts"].get(severity, 0) + 1
    if result["sbom"]:
        bom = result["sbom"]
        if result["vulnerability_report"]:
            append_missing_components(bom, result["vulnerability_report"])
        try:
            # Author, lifecycle, per-component CERT-In fields and the conformance attestation.
            from aspm_cli.certin.augment import augment_cyclonedx
            from aspm_cli.utils.certin_sbom import resolve_sbom_author
            report = augment_cyclonedx(bom, author=resolve_sbom_author(), lifecycle="analyzed", level="complete")
            result["certin"] = {"status": report["status"], "populated_pct": report["populated_pct"]}
        except ImportError:
            pass  # vendored where the CLI's CERT-In module is not installed (the backend)
        except Exception as exc:  # the SBOM is still valid without them
            result["coverage_reasons"].append(f"CERT-In fields were not added: {exc}")
        bom_path.write_text(json.dumps(bom), encoding="utf-8")
    components = (result["sbom"] or {}).get("components", [])
    result["component_count"] = len(components)
    if not components:
        result["coverage_reasons"].append("No dependency metadata was identified; this does not establish absence of vulnerabilities.")
    elif any(not c.get("version") or not c.get("purl") for c in components):
        result["coverage_reasons"].append("Some components lack a package identity or resolved version.")
    if kind in {"binary", "archive", "sbom"}:
        result["coverage_reasons"].append("Coverage is limited to discoverable package/version metadata; embedded or stripped dependencies may be unidentified.")
    # Declared dependency ranges are inventory evidence, not resolved versions.
    if any(re.search(r"[<>=~^*|, ]", str(c.get("version", ""))) for c in components):
        result["coverage_reasons"].append("Unresolved dependency version ranges require a lockfile or built artifact.")
    if kind == "manifest" and path.name in {"package.json", "pyproject.toml", "Cargo.toml"}:
        result["coverage_reasons"].append("This standalone manifest does not establish a resolved dependency inventory. Supply companion lockfiles in a directory.")
    if not result["coverage_reasons"]:
        result["coverage"] = "complete"
    failed = any(s["status"] == "failed" for s in result["stages"].values())
    successful = any(s["status"] == "completed" for s in result["stages"].values())
    result["status"] = "partial" if failed and successful else "failed" if failed else "completed"
    (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def validate_trivy(report):
    if not isinstance(report, dict) or not report.get("SchemaVersion") or not report.get("ArtifactType"):
        raise ArtifactError("Scanner returned an invalid vulnerability report.")
    if not isinstance(report.get("Results", []), list):
        raise ArtifactError("Invalid vulnerability results.")
    for entry in report.get("Results") or []:
        if not isinstance(entry, dict) or not isinstance(entry.get("Vulnerabilities", []), list):
            raise ArtifactError("Invalid vulnerability result entry.")
        for vuln in entry.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict) or not vuln.get("VulnerabilityID") or not vuln.get("PkgName"):
                raise ArtifactError("Vulnerability has no advisory or package identity.")


def result_exit_code(result, severities, softfail=False):
    if result.get("status") != "completed" or not result.get("component_count"):
        return 2
    if any(str(s).upper() in severities and count for s, count in result.get("finding_counts", {}).items()):
        return 0 if softfail else 1
    return 0
