"""Versions for C/C++ dependencies from a build that exists, or from a sandboxed CMake configure.

The scanned tree only names most system libraries (``#include <zlib.h>``, ``find_package(ZLIB)``);
the *version* lives in the build. Two sources, in order of preference:

1. **An existing build directory** (``CMakeCache.txt`` somewhere under the tree). Read only. It records what the
   customer's own build actually found.
2. **A throw-away CMake configure** into a temp directory, when ``cmake`` is installed and a sandbox that denies
   network access and writes outside that temp directory is available (macOS ``sandbox-exec``, Linux ``bwrap``).
   Without such a sandbox the configure is *not* run: it would execute the repository's own CMake code.
   This reports the libraries installed on the scanning machine, which equals the product's only when the scan
   runs on the build host, so it is labelled as such.

Never writes into the scanned tree. ``ACCUKNOX_BUILD_PROBE=off`` (or ``--no-build-probe``) disables both.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional, Tuple

ENV_SWITCH = "ACCUKNOX_BUILD_PROBE"
CONFIGURE_TIMEOUT = 60  # best effort: a configure still running after this rarely resolves anything
MAX_CACHE_DEPTH = 4
_PRUNE = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})

_CACHE_LINE_RE = re.compile(r"^([A-Za-z0-9_.+-]+):([A-Z]+)=(.*)$")
_VERSION_VAR_RE = re.compile(r"^([A-Za-z0-9_+-]+?)_VERSION(?:_STRING)?$")
_PACKAGE_VERSION_RE = re.compile(r'set\s*\(\s*PACKAGE_VERSION\s+"([0-9][^"]*)"\s*\)', re.IGNORECASE)
_DOTTED_RE = re.compile(r"^\d+(?:\.\d+)+[a-z]?$")
_NOT_A_PACKAGE = frozenset({"CMAKE", "CPACK", "CTEST", "PROJECT", "CMAKE_CXX_COMPILER", "CMAKE_C_COMPILER", "CMAKE_HOME_DIRECTORY"})


def enabled() -> bool:
    return os.environ.get(ENV_SWITCH, "on").strip().lower() not in ("off", "0", "false", "no")


def find_cache_files(root: str) -> List[str]:
    found: List[str] = []
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath.count(os.sep) - base_depth >= MAX_CACHE_DEPTH:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in _PRUNE and d != "CMakeFiles"]
        if "CMakeCache.txt" in filenames:
            found.append(os.path.join(dirpath, "CMakeCache.txt"))
    return sorted(found)


def parse_cmake_cache(path: str) -> Dict[str, Tuple[str, str]]:
    """``{NAME: (TYPE, value)}`` from a CMakeCache.txt."""
    entries: Dict[str, Tuple[str, str]] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith(("//", "#")):
                    continue
                match = _CACHE_LINE_RE.match(line.rstrip("\n"))
                if match:
                    entries[match.group(1)] = (match.group(2), match.group(3))
    except OSError:
        pass
    return entries


def _config_version(directory: str) -> Optional[str]:
    """``PACKAGE_VERSION`` from the ``*ConfigVersion.cmake`` next to a package's ``<Pkg>_DIR``."""
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return None
    for name in names:
        lower = name.lower()
        if lower.endswith("configversion.cmake") or lower.endswith("-config-version.cmake"):
            try:
                with open(os.path.join(directory, name), "r", encoding="utf-8", errors="replace") as handle:
                    match = _PACKAGE_VERSION_RE.search(handle.read(200_000))
            except OSError:
                continue
            if match:
                return match.group(1)
    return None


def _header_version(include_dirs: List[str], package: str) -> Optional[str]:
    """Version macros from the package's own headers inside the include directories CMake resolved."""
    from aspm_cli.inference.cpp import (
        _load_header_map,
        _name_variants,
        _read_text,
        _version_from_macros,
        _version_from_parts,
    )

    meta = _load_header_map().get(package, {})
    variants = _name_variants(package)
    candidates: List[str] = []
    for include_dir in include_dirs:
        for header in meta.get("headers", []):
            if header.endswith("*"):
                continue
            target = os.path.join(include_dir, header)
            if header.endswith("/") and os.path.isdir(target):
                try:
                    candidates += [os.path.join(target, n) for n in sorted(os.listdir(target))
                                   if "version" in n.lower() and n.lower().endswith((".h", ".hpp"))]
                except OSError:
                    pass
            elif os.path.isfile(target):
                candidates.append(target)
    for path in candidates[:20]:
        text = _read_text(path, 256_000)
        if text:
            found = _version_from_macros(text, variants) or _version_from_parts(text, variants)
            if found:
                return found
    return None


def _package_key(variable_prefix: str) -> Optional[Tuple[str, str]]:
    """(comparison key, header-map package or '') for a CMake variable prefix such as ``ZLIB`` or ``OpenSSL``."""
    from aspm_cli.inference.base import normalize_dep_name
    from aspm_cli.inference.cpp import _load_header_map, known_package

    if variable_prefix.upper() in _NOT_A_PACKAGE or variable_prefix.upper().startswith("CMAKE"):
        return None
    pkg = known_package(variable_prefix)
    if pkg:
        return normalize_dep_name(_load_header_map()[pkg]["conan"]), pkg
    return normalize_dep_name(variable_prefix), ""


def versions_from_cache(cache_path: str, entries: Dict[str, Tuple[str, str]], label: str) -> Dict[str, Tuple[str, str]]:
    """``{normalized name: (version, evidence)}`` from one CMake cache."""
    out: Dict[str, Tuple[str, str]] = {}

    def keep(key: str, version: Optional[str], evidence: str) -> None:
        if version and key not in out:
            out[key] = (version, evidence)

    include_dirs: Dict[str, List[str]] = {}
    for name, (kind, value) in entries.items():
        if name.endswith(("_INCLUDE_DIR", "_INCLUDE_DIRS")):
            include_dirs.setdefault(name.rsplit("_INCLUDE_DIR", 1)[0], []).extend(
                v for v in value.split(";") if v and os.path.isdir(v)
            )
    for name, (kind, value) in entries.items():
        key_info = None
        if name.endswith("_DIR") and kind == "PATH" and os.path.isdir(value) and "NOTFOUND" not in value:
            prefix = name[:-4]
            key_info = _package_key(prefix)
            if key_info:
                keep(key_info[0], _config_version(value), f"{label}:{name}")
        match = _VERSION_VAR_RE.match(name)
        if match and _DOTTED_RE.match(value):
            key_info = _package_key(match.group(1))
            if key_info:
                keep(key_info[0], value, f"{label}:{name}")
    for prefix, dirs in include_dirs.items():
        key_info = _package_key(prefix)
        if key_info and key_info[1]:
            keep(key_info[0], _header_version(dirs, key_info[1]), f"{label}:{prefix}_INCLUDE_DIR")
    return out


# ---- sandboxed configure -------------------------------------------------------------------


def _sandbox_prefix(tmp: str) -> Optional[List[str]]:
    """A command prefix that denies the network and writes outside ``tmp``; None when unavailable."""
    tmp = os.path.realpath(tmp)
    if sys.platform == "darwin" and shutil.which("sandbox-exec"):
        profile = (
            "(version 1)(allow default)(deny network*)"
            f'(deny file-write* (require-not (require-any (subpath "{tmp}") (literal "/dev/null")'
            ' (literal "/dev/tty") (literal "/dev/dtracehelper"))))'
        )
        prefix = ["sandbox-exec", "-p", profile]
    elif sys.platform.startswith("linux") and shutil.which("bwrap"):
        prefix = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--bind", tmp, tmp, "--tmpfs", "/tmp",
                  "--unshare-net", "--die-with-parent"]
    else:
        return None
    try:  # a sandbox that cannot even run `true` is as good as none
        if subprocess.run([*prefix, "true"], capture_output=True, timeout=10).returncode != 0:
            return None
    except (OSError, subprocess.SubprocessError):
        return None
    return prefix


@contextmanager
def cmake_configure_cache(root: str, log=None) -> Iterator[Optional[str]]:
    """Yield the CMakeCache.txt of a sandboxed configure of ``root``, or None. The temp dir is always removed."""
    cmake = shutil.which("cmake")
    if not cmake or not os.path.isfile(os.path.join(root, "CMakeLists.txt")):
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="accuknox-cmake-probe-") as tmp:
        prefix = _sandbox_prefix(tmp)
        if prefix is None:
            if log:
                log.info("cmake is available but no network-denying sandbox is; not running the repository's CMake. "
                         "Dependency versions come from the source tree only.")
            yield None
            return
        command = [*prefix, cmake, "-S", os.path.realpath(root), "-B", os.path.join(os.path.realpath(tmp), "build"),
                   "-DFETCHCONTENT_FULLY_DISCONNECTED=ON", "--no-warn-unused-cli"]
        try:
            subprocess.run(command, cwd=tmp, capture_output=True, timeout=CONFIGURE_TIMEOUT, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            pass  # a configure that fails part-way still leaves a cache of what it found
        cache = os.path.join(tmp, "build", "CMakeCache.txt")
        yield cache if os.path.isfile(cache) else None


def collect_build_versions(root: str, log=None) -> Dict[str, Tuple[str, str, str]]:
    """``{normalized name: (version, evidence, origin)}``; origin is ``build-output`` or ``cmake-configure``."""
    if not enabled():
        return {}
    versions: Dict[str, Tuple[str, str, str]] = {}
    caches = find_cache_files(root)
    for path in caches:
        rel = os.path.relpath(path, root)
        for key, (version, evidence) in versions_from_cache(path, parse_cmake_cache(path), rel).items():
            versions.setdefault(key, (version, evidence, "build-output"))
    if caches:
        return versions
    with cmake_configure_cache(root, log) as cache:
        if cache:
            for key, (version, evidence) in versions_from_cache(cache, parse_cmake_cache(cache), "cmake configure").items():
                versions.setdefault(key, (version, evidence, "cmake-configure"))
    return versions
