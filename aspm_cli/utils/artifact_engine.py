"""Portable artifact scanner, vendored identically in the CLI and backend.

No application imports: both callers use this contract with their own tool executor.
Sync with scripts/sync-artifact-engine.py after editing this file.
"""
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
import zipfile
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


class ArtifactError(ValueError):
    pass


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


def detect_target(path, requested="auto"):
    path = Path(path)
    if path.is_symlink():
        raise ArtifactError("Symbolic links are unsupported.")
    if requested not in TARGET_TYPES:
        raise ArtifactError("Unsupported target type.")
    if not path.exists() or path.is_symlink():
        raise ArtifactError("Target must exist and cannot be a symbolic link.")
    if path.is_dir():
        detected = "directory"
    elif not path.is_file():
        raise ArtifactError("Target must be a regular file or directory.")
    else:
        if path.stat().st_size > MAX_BYTES:
            raise ArtifactError("Artifact exceeds the 512 MiB upload limit.")
        with path.open("rb") as stream:
            magic = stream.read(4)
        if path.suffix.lower() in {".apk", ".ipa"}:
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
        elif zipfile.is_zipfile(path) or tarfile.is_tarfile(path) or path.suffix.lower() in {".rpm", ".deb"}:
            detected = "archive"
        else:
            raise ArtifactError("Unsupported input. Supply a supported manifest, SBOM, executable, or package archive.")
    if requested != "auto" and requested != detected:
        raise ArtifactError(f"Target is {detected}, not {requested}.")
    return detected


def fingerprint(path):
    path = Path(path)
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
                if total > MAX_EXPANDED:
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


def extract_archive(path, destination):
    """Validate every member before extraction; never restore permissions or links."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    names = set()
    total = 0
    def check(name, size):
        nonlocal total
        member = safe_member(name)
        key = str(member).casefold()
        if key in names:
            raise ArtifactError("Duplicate archive path.")
        names.add(key)
        total += size
        if len(names) > MAX_MEMBERS or total > MAX_EXPANDED:
            raise ArtifactError("Archive exceeds expansion limits.")
        return destination.joinpath(*member.parts)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            members = []
            for item in archive.infolist():
                target = check(item.filename, item.file_size)
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


def native_executor(tool, args, workdir):
    try:
        subprocess.run([tool, *args], cwd=workdir, check=True, timeout=1200,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except (OSError, subprocess.SubprocessError) as exc:
        diagnostic = Path(workdir) / f"{Path(tool).name}.log"
        stderr = getattr(exc, "stderr", None)
        diagnostic.write_bytes(stderr[-65536:] if isinstance(stderr, bytes) else str(exc).encode()[-65536:])
        raise ArtifactError(f"Scanner failed. Check installation/databases and {diagnostic}.") from exc


def scan_artifact(target, output_dir, target_type="auto", asset_name=None, project_name=None,
                  syft="syft", trivy="trivy", sbom_only=False, execute=native_executor, on_stage=None):
    """Return a versioned, portable result envelope; inputs are never rewritten."""
    path = Path(target).resolve()
    kind = detect_target(target, target_type)
    sha256, size = fingerprint(path)
    output = Path(output_dir).resolve()
    # Output must not be inside a directory being scanned.
    if path.is_dir() and (output == path or path in output.parents):
        raise ArtifactError("The result directory must be outside the scan target.")
    output.mkdir(parents=True, exist_ok=True)
    artifact = {"filename": path.name, "name": asset_name or path.name, "type": kind,
                "sha256": sha256, "size": size, "project_name": project_name or ""}
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
    scan_path = path
    # General bundles are extracted; Java and OS package archives use file catalogers.
    if kind == "archive" and path.suffix.lower() not in {".jar", ".war", ".ear", ".par", ".rpm", ".deb"}:
        scan_path = extract_archive(path, output / "contents")
    bom_path = output / "sbom.json"
    def inventory():
        if kind == "sbom":
            execute(syft, ["convert", str(path), "-o", f"cyclonedx-json={bom_path}"], output)
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
    if not sbom_only:
        def vulnerabilities():
            report_path = output / "vulnerabilities.json"
            # Source targets need filesystem analyzers; built artifacts use their SBOM.
            if kind in {"manifest", "directory"}:
                args = ["fs", str(scan_path), "--skip-dirs", ".git", "--scanners", "vuln", "--list-all-pkgs"]
            else:
                if not result["sbom"]:
                    raise ArtifactError("Vulnerability scanning requires a successful inventory.")
                args = ["sbom", str(bom_path)]
            execute(trivy, [*args, "--format", "json", "--output", str(report_path), "--exit-code", "0", "--quiet"], output)
            report = read_json(report_path)
            validate_trivy(report)
            for entry in report.get("Results") or []:
                for vuln in entry.get("Vulnerabilities") or []:
                    severity = str(vuln.get("Severity", "UNKNOWN")).upper()
                    result["finding_counts"][severity] = result["finding_counts"].get(severity, 0) + 1
            return report
        result["vulnerability_report"] = stage("vulnerabilities", vulnerabilities)
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
