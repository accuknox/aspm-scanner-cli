"""C/C++ dependency inference from source includes and build files.

Evidence, strongest first:
  A  explicit and versioned: CMake FetchContent/ExternalProject/CPM, vcpkg.json overrides,
     .gitmodules + gitlink, MODULE.bazel bazel_dep, Meson wraps
  B  version sniffed from a vendored tree (VERSION file, project(VERSION), header macro)
  C  name only: an #include of a known package, or a version *constraint* (find_package(X 1.2)
     means ">= 1.2", not a resolved version)

Nothing here touches the network or writes into the tree.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from functools import lru_cache
from typing import Dict, Iterator, List, Optional, Set, Tuple

from aspm_cli.inference.base import (
    CONFIDENCE_A,
    CONFIDENCE_B,
    CONFIDENCE_C,
    SOURCE_GIT,
    SOURCE_INCLUDE,
    SOURCE_REGISTRY,
    SOURCE_VENDORED,
    InferenceResult,
    InferredDep,
    LanguageInferrer,
    normalize_dep_name,
    strip_url_credentials,
)

CPP_EXTENSIONS = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".ipp", ".inl", ".cu", ".cuh", ".m", ".mm"}
)
HEADER_EXTENSIONS = frozenset({".h", ".hh", ".hpp", ".hxx", ".ipp", ".inl", ".cuh"})
MAX_SOURCE_BYTES = 1_000_000
MAX_FILES = 50_000
PRUNE_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", "__pycache__", ".idea", ".vscode", "CMakeFiles", "_deps", ".cache"}
)
VENDOR_DIRS = frozenset(
    {"third_party", "third-party", "thirdparty", "extern", "external", "externals", "vendor", "deps", "ext", "contrib", "3rdparty"}
)
# Directory names that are never a package ("include", "src", ...) even when found under a vendor dir.
GENERIC_DIR_NAMES = frozenset(
    {"include", "includes", "src", "source", "lib", "libs", "bin", "doc", "docs", "test", "tests", "cmake",
     "build", "scripts", "tools", "examples", "samples", "data", "licenses", "license", "patches"}
)
WRAPPER_SUFFIXES = ("-cmake", "_cmake")  # build glue next to a dependency, e.g. contrib/zlib-ng-cmake

# C/C++ standard + POSIX/system header roots that are never third-party dependencies.
_SYSTEM_PREFIXES = (
    "sys/", "linux/", "netinet/", "arpa/", "bits/", "asm/", "asm-generic/", "net/", "mach/", "mach-o/",
    "os/", "cuda", "windows", "dispatch/", "objc/", "sanitizer/", "gnu/", "machine/", "x86intrin", "arm_",
    "emscripten/", "gl/", "gles", "egl/", "opengl/", "android/", "alsa/", "pulse/", "jack/", "coreaudio/",
    "audiotoolbox/", "avfoundation/", "mmdeviceapi", "dsound", "winapi/",
)
_C_STD = frozenset(
    """assert.h complex.h ctype.h errno.h fenv.h float.h inttypes.h iso646.h limits.h locale.h math.h setjmp.h
    signal.h stdalign.h stdarg.h stdatomic.h stdbool.h stddef.h stdint.h stdio.h stdlib.h stdnoreturn.h string.h
    tgmath.h threads.h time.h uchar.h wchar.h wctype.h unistd.h fcntl.h dirent.h pthread.h semaphore.h dlfcn.h
    poll.h pwd.h grp.h regex.h netdb.h termios.h getopt.h libgen.h glob.h fnmatch.h ifaddrs.h syslog.h utime.h
    wordexp.h strings.h search.h langinfo.h nl_types.h spawn.h sched.h mqueue.h ftw.h iconv.h malloc.h alloca.h
    endian.h byteswap.h execinfo.h elf.h link.h ucontext.h mman.h ioctl.h windows.h winsock2.h ws2tcpip.h
    process.h io.h direct.h tchar.h conio.h immintrin.h emmintrin.h xmmintrin.h smmintrin.h arm_neon.h
    Windows.h WinSock2.h""".split()
)

_C_STD_LOWER = frozenset(h.lower() for h in _C_STD) | frozenset(
    """emscripten.h jni.h dos.h intrin.h memory.h crtdbg.h wasm_simd128.h malloc.h stdalign.h cpuid.h
    x86intrin.h arm_acle.h android_native_app_glue.h pthread_np.h kernel.h os.h""".split()
)
_INCLUDE_RE = re.compile(r'^\s*#\s*(?:include|include_next|import)\s*([<"])([^>"\n]+)[>"]', re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_IF0_RE = re.compile(r"^\s*#\s*if\s+0\b.*?^\s*#\s*(?:endif|else)\b", re.MULTILINE | re.DOTALL)
_VERSION_RE = re.compile(r"\d+(?:\.\d+)+[a-z]?")
_SEMVER_TAG_RE = re.compile(r"^(?:[A-Za-z][A-Za-z_-]*[-_]?)?v?(\d+(?:[._]\d+)+[a-z]?)$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@lru_cache(maxsize=1)
def _load_header_map() -> Dict[str, dict]:
    path = os.path.join(os.path.dirname(__file__), "header_map.json")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)["packages"]


@lru_cache(maxsize=1)
def _header_index() -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    """(exact header -> package, [(dir prefix, package)] longest first)."""
    exact: Dict[str, str] = {}
    prefixes: List[Tuple[str, str]] = []
    for pkg, meta in _load_header_map().items():
        for header in meta.get("headers", []):
            key = header.lower()
            if key.endswith("*"):  # "SDL_*" = any header starting with "SDL_"
                prefixes.append((key[:-1], pkg))
            elif key.endswith("/"):
                prefixes.append((key, pkg))
            else:
                exact[key] = pkg
    prefixes.sort(key=lambda item: -len(item[0]))
    return exact, prefixes


@lru_cache(maxsize=1)
def _alias_index() -> Dict[str, str]:
    """normalized alias / package / conan / vcpkg name -> package key."""
    index: Dict[str, str] = {}
    for pkg, meta in _load_header_map().items():
        for name in [pkg, meta.get("conan"), meta.get("vcpkg"), *meta.get("aliases", [])]:
            if name:
                index.setdefault(normalize_dep_name(name), pkg)
    return index


def known_package(name: str) -> Optional[str]:
    return _alias_index().get(normalize_dep_name(name))


def package_for_header(include_path: str) -> Optional[str]:
    exact, prefixes = _header_index()
    key = include_path.lower()
    if key in exact:
        return exact[key]
    for prefix, pkg in prefixes:
        if key.startswith(prefix):
            return pkg
    return None


def is_system_header(include_path: str) -> bool:
    key = include_path.lower()
    base = key.rsplit("/", 1)[-1]
    if "/" not in key and "." not in base:
        return True  # extension-less => C++ standard library (<vector>, <string>, ...)
    if "/" not in key and key in _C_STD_LOWER:
        return True
    return key.startswith(_SYSTEM_PREFIXES)


def _conan_purl(name: str, version: Optional[str]) -> str:
    return f"pkg:conan/{name}@{version}" if version else f"pkg:conan/{name}"


def _generic_purl(name: str, version: Optional[str], vcs_url: Optional[str] = None) -> str:
    purl = f"pkg:generic/{name}" + (f"@{version}" if version else "")
    if vcs_url:
        purl += "?vcs_url=" + vcs_url.replace("&", "%26")
    return purl


def _git_purl(name: str, version: Optional[str], url: Optional[str]) -> Tuple[str, Optional[str]]:
    """Purl for a git-sourced dependency; github.com remotes get pkg:github, others pkg:generic."""
    clean = strip_url_credentials(url or "") if url else ""
    match = re.match(r"^(?:https?://|git@|ssh://git@)?github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$", clean)
    if match:
        return f"pkg:github/{match.group(1).lower()}/{match.group(2).lower()}" + (f"@{version}" if version else ""), clean
    return _generic_purl(name, version, clean or None), clean or None


def _tag_version(ref: Optional[str]) -> Optional[str]:
    """A release-looking tag (v1.2.3, zlib-1.2.11, release-1.2) -> '1.2.3'; branches/SHAs -> None."""
    if not ref:
        return None
    match = _SEMVER_TAG_RE.match(ref.strip())
    return match.group(1).replace("_", ".") if match else None


def _strip_comments(text: str) -> str:
    text = _BLOCK_COMMENT_RE.sub(" ", text)
    text = _IF0_RE.sub("\n", text)
    return _LINE_COMMENT_RE.sub("", text)


def _read_text(path: str, limit: int = MAX_SOURCE_BYTES) -> Optional[str]:
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _walk(root: str) -> Iterator[Tuple[str, List[str]]]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
        yield dirpath, filenames


def _rel(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def _in_vendor(rel_path: str) -> Optional[str]:
    """Name of the vendored dependency a path lives in (third_party/<name>/...), else None."""
    parts = rel_path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part.lower() in VENDOR_DIRS and i + 1 < len(parts) - 1:
            return parts[i + 1]
    return None


def _submodule_paths(root: str) -> List[str]:
    text = _read_text(os.path.join(root, ".gitmodules"), 256_000) or ""
    return [m.group(1).strip().strip("/") for m in re.finditer(r"^\s*path\s*=\s*(\S+)", text, re.MULTILINE)]


def _in_dependency(rel_path: str, submodule_paths: List[str]) -> bool:
    """True for a file that belongs to a vendored dependency or a submodule, not to the project itself."""
    if _in_vendor(rel_path):
        return True
    return any(rel_path == sp or rel_path.startswith(sp + "/") for sp in submodule_paths)


def sniff_vendored_version(directory: str, name: str) -> Optional[str]:
    """Best-effort version of a vendored tree: VERSION file, project(VERSION), then header macros."""
    for fname in ("VERSION", "VERSION.txt", "version.txt", ".version"):
        text = _read_text(os.path.join(directory, fname), 4096)
        if text:
            match = _VERSION_RE.search(text)
            if match:
                return match.group(0)
    cmake = _read_text(os.path.join(directory, "CMakeLists.txt"), 512_000)
    if cmake:
        match = re.search(r"project\s*\([^)]*?\bVERSION\s+(\d+(?:\.\d+)+)", cmake, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)
    macro = re.compile(
        r'#\s*define\s+\w*VERSION\w*\s+"?[^"\n]*?(\d+\.\d+(?:\.\d+)*[a-z]?)', re.IGNORECASE
    )
    wanted = normalize_dep_name(name)
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS and d not in ("test", "tests", "doc", "docs", "examples")]
        if dirpath[len(directory):].count(os.sep) > 3:
            dirnames[:] = []
        for fname in sorted(filenames):
            stem, ext = os.path.splitext(fname)
            if ext.lower() not in HEADER_EXTENSIONS:
                continue
            if "version" not in stem.lower() and not normalize_dep_name(stem).startswith(wanted):
                continue
            scanned += 1
            if scanned > 40:
                return None
            text = _read_text(os.path.join(dirpath, fname), 256_000)
            if text:
                match = macro.search(text)
                if match:
                    return match.group(1)
    return None


def _is_ci_or_docker(rel: str, lower: str) -> bool:
    if lower.startswith("dockerfile") or lower.endswith(".dockerfile") or lower == "jenkinsfile":
        return True
    if lower in (".gitlab-ci.yml", "azure-pipelines.yml", "azure-pipelines.yaml", "bitbucket-pipelines.yml"):
        return True
    return lower.endswith((".yml", ".yaml")) and (rel.startswith(".github/workflows/") or rel.startswith(".circleci/"))


_INSTALLERS = {  # tool -> subcommands that install
    "apt-get": {"install"}, "apt": {"install"}, "apk": {"add"}, "yum": {"install"}, "dnf": {"install"},
    "brew": {"install"}, "vcpkg": {"install"}, "conan": {"install", "create", "download", "lock"},
}
_INSTALL_RE = re.compile(r"(?:^|[\s;&|(`'\"])(apt-get|apt|apk|yum|dnf|brew|vcpkg|conan)\s+([a-z]+)\b([^\n;&|`'\"]*)")
_CLI_ONLY_BREW = frozenset({"curl", "wget"})
_CONAN_REF_RE = re.compile(r"^([a-z0-9_.+-]+)/(\d+(?:\.\d+)+[a-z]?)(?:[@#%].*)?$")


def _system_package_name(token: str) -> Tuple[str, Optional[str]]:
    """'libssl-dev=1.1.1f-1ubuntu2:amd64' -> ('libssl-dev', '1.1.1f-1ubuntu2')."""
    name, _, version = token.partition("=")
    name = name.split(":", 1)[0].split("@", 1)[0]  # arch suffix, brew 'openssl@3'

    return name, (version.split(":", 1)[0] or None) if version else None


def _known_from_package_name(name: str) -> Optional[str]:
    """Match a distro/brew/vcpkg package name ('libboost-all-dev', 'libpng-dev') to a known package."""
    base = name.lower()
    variants = [base]
    stripped = re.sub(r"-(?:dev|devel|dbg|static)$", "", base)
    variants.append(stripped)
    for v in (stripped, base):
        if v.startswith("lib"):
            variants.append(v[3:])
    variants.extend(v.split("-", 1)[0] for v in list(variants) if "-" in v)
    for v in variants:
        pkg = known_package(v) or known_package(re.sub(r"\d+$", "", v))
        if pkg:
            return pkg
    return None


class CppInferrer(LanguageInferrer):
    language = "cpp"

    # ---- public API -------------------------------------------------------------------------
    def detect(self, root: str) -> bool:
        for _dirpath, filenames in _walk(root):
            if any(os.path.splitext(f)[1].lower() in CPP_EXTENSIONS for f in filenames):
                return True
            if "CMakeLists.txt" in filenames or "meson.build" in filenames:
                return True
        return False

    def infer(self, root: str, existing_names: Optional[Set[str]] = None) -> InferenceResult:
        root = os.path.abspath(root)
        result = InferenceResult()
        found: Dict[str, InferredDep] = {}

        def add(dep: InferredDep) -> None:
            key = normalize_dep_name(dep.name)
            current = found.get(key)
            if current is None:
                found[key] = dep
                return
            # Keep the stronger evidence (A beats B beats C; resolved version beats none).
            rank = {CONFIDENCE_A: 0, CONFIDENCE_B: 1, CONFIDENCE_C: 2}
            if (rank[dep.confidence], dep.version is None) < (rank[current.confidence], current.version is None):
                dep.evidence = list(dict.fromkeys(dep.evidence + current.evidence))
                found[key] = dep
            else:
                current.evidence = list(dict.fromkeys(current.evidence + dep.evidence))

        all_files: Dict[str, List[str]] = {}  # basename -> [rel paths], for first-party resolution
        source_files: List[str] = []
        for dirpath, filenames in _walk(root):
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                rel = _rel(root, full)
                all_files.setdefault(fname, []).append(rel)
                if os.path.splitext(fname)[1].lower() in CPP_EXTENSIONS and len(source_files) < MAX_FILES:
                    source_files.append(rel)

        submodules = _submodule_paths(root)
        for dep in self._build_file_deps(root, submodules):
            add(dep)
        for dep in self._vendored_deps(root, source_files, submodules):
            add(dep)
        self._include_deps(root, source_files, all_files, result, add, submodules)

        skip = {normalize_dep_name(n) for n in (existing_names or set())}
        result.files_scanned = len(source_files)
        result.deps = sorted(
            (d for key, d in found.items() if key not in skip), key=lambda d: (d.confidence, d.name.lower())
        )
        return result

    # ---- includes ---------------------------------------------------------------------------
    def _include_deps(self, root, source_files, all_files, result, add, submodules=()) -> None:
        seen: Dict[str, List[str]] = {}
        for rel in source_files:
            if _in_dependency(rel, list(submodules)):
                continue  # a dependency's own includes are not our dependencies
            text = _read_text(os.path.join(root, rel))
            if not text:
                continue
            clean = _strip_comments(text)
            for match in _INCLUDE_RE.finditer(clean):
                inc = match.group(2).strip()
                line = clean.count("\n", 0, match.start()) + 1
                seen.setdefault(inc, []).append(f"{rel}:{line}")
        for inc, where in seen.items():
            if is_system_header(inc):
                continue
            if self._is_first_party(inc, all_files):
                continue
            pkg = package_for_header(inc)
            if pkg:
                meta = _load_header_map()[pkg]
                result_name = meta["conan"]
                add(
                    InferredDep(
                        name=result_name,
                        version=None,
                        purl=_conan_purl(result_name, None),
                        ecosystem="conan",
                        confidence=CONFIDENCE_C,
                        source=SOURCE_INCLUDE,
                        evidence=where[:3],
                        kind="source-import",
                    )
                )
            else:
                result.unresolved_includes[inc] = len(where)

    @staticmethod
    def _is_first_party(inc: str, all_files: Dict[str, List[str]]) -> bool:
        # "../x/y.h" and "./y.h" are relative to the including file: drop the leading ./ and ../ parts.
        parts = [p for p in inc.split("/")]
        while parts and parts[0] in (".", ".."):
            parts.pop(0)
        inc = "/".join(parts)
        if not inc:
            return False
        candidates = all_files.get(parts[-1], [])
        return any(c == inc or c.endswith("/" + inc) for c in candidates)

    # ---- vendored trees ---------------------------------------------------------------------
    def _vendored_deps(self, root, source_files, submodules=()) -> List[InferredDep]:
        deps: List[InferredDep] = []
        seen: Set[str] = set()
        submodules = list(submodules)
        for dirpath, dirnames, _files in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
            rel_dir = _rel(root, dirpath) if dirpath != root else ""
            if any(rel_dir == sp or rel_dir.startswith(sp + "/") for sp in submodules):
                dirnames[:] = []  # inside a submodule: its own layout is not ours to enumerate
                continue
            if rel_dir.count("/") + (1 if rel_dir else 0) > 4:
                dirnames[:] = []
                continue
            if os.path.basename(dirpath).lower() not in VENDOR_DIRS:
                continue
            for child in sorted(dirnames):
                path = os.path.join(dirpath, child)
                rel = _rel(root, path)
                if (rel in seen or child.lower() in GENERIC_DIR_NAMES or rel in submodules
                        or not any(True for _ in os.scandir(path))):
                    continue
                seen.add(rel)
                wrapper = child.lower().endswith(WRAPPER_SUFFIXES)
                name = child[:-6] if wrapper else child
                # A "-cmake" wrapper is build glue: its own version is not the dependency's version.
                version = None if wrapper else sniff_vendored_version(path, child)
                pkg = known_package(name)
                evidence = [rel + "/"]
                if pkg and version:
                    conan = _load_header_map()[pkg]["conan"]
                    deps.append(InferredDep(conan, version, _conan_purl(conan, version), "conan",
                                            CONFIDENCE_B, SOURCE_VENDORED, evidence, kind="vendored"))
                else:
                    deps.append(InferredDep(name, version, _generic_purl(name, version), "generic",
                                            CONFIDENCE_B if version else CONFIDENCE_C, SOURCE_VENDORED,
                                            evidence, kind="vendored"))
            dirnames[:] = []  # children of a vendor dir are the deps themselves
        return deps

    # ---- build files ------------------------------------------------------------------------
    def _build_file_deps(self, root: str, submodules=()) -> List[InferredDep]:
        deps: List[InferredDep] = []
        submodules = list(submodules)
        for dirpath, filenames in _walk(root):
            for fname in filenames:
                path = os.path.join(dirpath, fname)
                rel = _rel(root, path)
                if _in_dependency(rel, submodules):
                    continue  # a dependency's own build files describe its dependencies, not ours
                lower = fname.lower()
                if lower == "cmakelists.txt" or lower.endswith(".cmake"):
                    deps.extend(self._cmake(path, rel, root))
                elif lower == "vcpkg.json":
                    deps.extend(self._vcpkg(path, rel))
                elif lower == "module.bazel":
                    deps.extend(self._bazel_module(path, rel))
                elif _is_ci_or_docker(rel, lower):
                    deps.extend(self._ci_commands(path, rel))
                elif lower in ("workspace", "workspace.bazel"):
                    deps.extend(self._bazel_workspace(path, rel, root))
                elif lower == "meson.build":
                    deps.extend(self._meson_build(path, rel))
                elif lower in ("configure.ac", "configure.in"):
                    deps.extend(self._autotools(path, rel))
                elif lower.endswith(".wrap") and os.path.basename(dirpath) == "subprojects":
                    deps.extend(self._meson_wrap(path, rel))
        deps.extend(self._gitmodules(root))
        return deps

    def _git_dep(self, name, url, ref, evidence, root_dir, kind, directory=None) -> InferredDep:
        """A git-sourced dependency; promoted to a registry purl only if its version can be resolved."""
        version = _tag_version(ref)
        if not version and directory and os.path.isdir(directory):
            version = sniff_vendored_version(directory, name)
        pkg = known_package(name)
        if pkg and version:
            conan = _load_header_map()[pkg]["conan"]
            return InferredDep(conan, version, _conan_purl(conan, version), "conan", CONFIDENCE_A if _tag_version(ref) else CONFIDENCE_B,
                               SOURCE_REGISTRY, evidence, repo_url=strip_url_credentials(url or "") or None, kind=kind)
        ref_version = version or (ref if ref and _SHA_RE.match(ref) else None)
        purl, clean_url = _git_purl(name, ref_version, url)
        return InferredDep(name, version or ref_version, purl, "github" if purl.startswith("pkg:github") else "generic",
                           CONFIDENCE_A if ref_version else CONFIDENCE_C, SOURCE_GIT, evidence, repo_url=clean_url, kind=kind)

    def _cmake(self, path: str, rel: str, root: str) -> List[InferredDep]:
        text = _read_text(path)
        if not text:
            return []
        text = re.sub(r"#[^\n]*", "", text)
        out: List[InferredDep] = []

        def line_of(pos: int) -> str:
            return f"{rel}:{text.count(chr(10), 0, pos) + 1}"

        for m in re.finditer(r"\bfind_package\s*\(\s*([A-Za-z0-9_+.-]+)([^)]*)\)", text, re.IGNORECASE):
            name, rest = m.group(1), m.group(2)
            pkg = known_package(name)
            if not pkg:
                continue
            ver = re.search(r"(?:^|\s)(\d+(?:\.\d+)+)(?=\s|$)", rest)
            conan = _load_header_map()[pkg]["conan"]
            exact = "EXACT" in rest.upper().split()
            if ver and exact:
                out.append(InferredDep(conan, ver.group(1), _conan_purl(conan, ver.group(1)), "conan", CONFIDENCE_A,
                                       SOURCE_REGISTRY, [line_of(m.start())], kind="build-file"))
            else:
                out.append(InferredDep(conan, None, _conan_purl(conan, None), "conan", CONFIDENCE_C, SOURCE_INCLUDE,
                                       [line_of(m.start())], constraint=(">=" + ver.group(1)) if ver else None,
                                       kind="build-file"))

        for m in re.finditer(r"\b(FetchContent_Declare|ExternalProject_Add)\s*\(\s*([A-Za-z0-9_.+-]+)((?:[^()]|\([^()]*\))*)\)",
                             text, re.IGNORECASE):
            name, body = m.group(2), m.group(3)
            url = re.search(r"GIT_REPOSITORY\s+(\S+)", body)
            tag = re.search(r"GIT_TAG\s+(\S+)", body)
            if url:
                directory = None
                src = re.search(r"SOURCE_DIR\s+(\S+)", body)
                if src and "${" not in src.group(1):
                    directory = os.path.join(root, src.group(1))
                out.append(self._git_dep(name, url.group(1).strip('"'), tag.group(1).strip('"') if tag else None,
                                         [line_of(m.start())], root, "build-file", directory))
                continue
            archive = re.search(r"\bURL\s+(\S+)", body)
            if archive:
                ver = _VERSION_RE.search(archive.group(1).rsplit("/", 1)[-1])
                pkg = known_package(name)
                if pkg and ver:
                    conan = _load_header_map()[pkg]["conan"]
                    out.append(InferredDep(conan, ver.group(0), _conan_purl(conan, ver.group(0)), "conan", CONFIDENCE_A,
                                           SOURCE_REGISTRY, [line_of(m.start())], kind="build-file"))
                else:
                    out.append(InferredDep(name, ver.group(0) if ver else None, _generic_purl(name, ver.group(0) if ver else None,
                                           strip_url_credentials(archive.group(1))), "generic", CONFIDENCE_A if ver else CONFIDENCE_C,
                                           SOURCE_GIT, [line_of(m.start())], kind="build-file"))

        for m in re.finditer(r"\bCPMAddPackage\s*\(((?:[^()]|\([^()]*\))*)\)", text, re.IGNORECASE):
            body = m.group(1).strip()
            short = re.match(r'"?gh:([^/@"\s]+)/([^/@"\s]+)(?:@(\S+?))?"?$', body)
            if short:
                out.append(self._git_dep(short.group(2), f"https://github.com/{short.group(1)}/{short.group(2)}",
                                         short.group(3), [line_of(m.start())], root, "build-file"))
                continue
            name = re.search(r"\bNAME\s+(\S+)", body)
            gh = re.search(r"GITHUB_REPOSITORY\s+(\S+)", body)
            git = re.search(r"GIT_REPOSITORY\s+(\S+)", body)
            ref = re.search(r"\b(?:GIT_TAG|VERSION)\s+(\S+)", body)
            url = f"https://github.com/{gh.group(1)}" if gh else (git.group(1) if git else None)
            nm = name.group(1) if name else (url.rsplit("/", 1)[-1].removesuffix(".git") if url else None)
            if nm:
                out.append(self._git_dep(nm, url, ref.group(1) if ref else None, [line_of(m.start())], root, "build-file"))
        return out

    def _vcpkg(self, path: str, rel: str) -> List[InferredDep]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return []
        if not isinstance(data, dict):
            return []
        overrides = {o.get("name"): o.get("version") for o in data.get("overrides", []) if isinstance(o, dict)}
        out: List[InferredDep] = []
        for entry in data.get("dependencies", []):
            name = entry if isinstance(entry, str) else (entry or {}).get("name")
            if not name:
                continue
            minimum = None if isinstance(entry, str) else entry.get("version>=")
            pkg = known_package(name)
            conan = _load_header_map()[pkg]["conan"] if pkg else name
            version = overrides.get(name)
            if version:
                out.append(InferredDep(conan, version, _conan_purl(conan, version) if pkg else _generic_purl(name, version),
                                       "conan" if pkg else "generic", CONFIDENCE_A, SOURCE_REGISTRY if pkg else SOURCE_GIT,
                                       [rel], kind="build-file"))
            else:
                out.append(InferredDep(conan, None, _conan_purl(conan, None) if pkg else _generic_purl(name, None),
                                       "conan" if pkg else "generic", CONFIDENCE_C, SOURCE_INCLUDE, [rel],
                                       constraint=f">={minimum}" if minimum else None, kind="build-file"))
        return out

    def _bazel_module(self, path: str, rel: str) -> List[InferredDep]:
        text = _read_text(path)
        if not text:
            return []
        out: List[InferredDep] = []
        for m in re.finditer(r"bazel_dep\s*\(([^)]*)\)", text):
            body = m.group(1)
            name = re.search(r'name\s*=\s*"([^"]+)"', body)
            version = re.search(r'version\s*=\s*"([^"]+)"', body)
            if not name or name.group(1).startswith("rules_") or name.group(1) in ("platforms", "bazel_skylib"):
                continue
            ver = version.group(1) if version else None
            pkg = known_package(name.group(1))
            line = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
            if pkg and ver:
                conan = _load_header_map()[pkg]["conan"]
                out.append(InferredDep(conan, ver, _conan_purl(conan, ver), "conan", CONFIDENCE_A, SOURCE_REGISTRY, [line], kind="build-file"))
            else:
                out.append(InferredDep(name.group(1), ver, _generic_purl(name.group(1), ver), "generic",
                                       CONFIDENCE_A if ver else CONFIDENCE_C, SOURCE_GIT, [line], kind="build-file"))
        return out

    def _ci_commands(self, path: str, rel: str) -> List[InferredDep]:
        """Packages named by install commands in a Dockerfile or CI config.

        A distro/brew/vcpkg install names a package but no upstream version (distro versions are
        patched builds), so those are constraint-only; an explicit Conan reference resolves one.
        """
        text = _read_text(path)
        if not text:
            return []
        text = re.sub(r"\\\n", " ", text)  # join line continuations
        out: List[InferredDep] = []
        for m in _INSTALL_RE.finditer(text):
            tool, sub, rest = m.group(1), m.group(2), m.group(3)
            if sub not in _INSTALLERS[tool]:
                continue
            line = f"{rel}:{text.count(chr(10), 0, m.start(1)) + 1}"
            tokens = rest.split()
            skip_next = False
            for i, tok in enumerate(tokens):
                if skip_next:
                    skip_next = False
                    continue
                if tool == "conan":
                    ref = tok.split("=", 1)[1] if tok.startswith("--requires=") else (
                        tokens[i + 1] if tok == "--requires" and i + 1 < len(tokens) else (tok if not tok.startswith("-") else ""))
                    if tok == "--requires":
                        skip_next = True
                    found = _CONAN_REF_RE.match(ref.strip("\"'"))
                    if found:
                        out.append(InferredDep(found.group(1), found.group(2), _conan_purl(found.group(1), found.group(2)),
                                               "conan", CONFIDENCE_A, SOURCE_REGISTRY, [line], kind="ci-config"))
                    continue
                if tok.startswith("-"):
                    skip_next = tok in ("--virtual", "-t", "--target-release", "--triplet")
                    continue
                if tok in ("sudo", "\\") or "$" in tok or "/" in tok or tok.startswith((".", "@")):
                    continue
                name, version = _system_package_name(tok.split(":", 1)[0] if tool == "vcpkg" else tok)
                # A bare distro package ('curl', 'openssl') is usually the CLI tool; a library install
                # is named lib*/-dev/-devel. brew and vcpkg are library ecosystems.
                library_marked = name.startswith("lib") or name.endswith(("-dev", "-devel", "-static"))
                if tool in ("apt-get", "apt", "apk", "yum", "dnf") and not library_marked:
                    continue
                if tool == "brew" and name in _CLI_ONLY_BREW:
                    continue
                pkg = _known_from_package_name(name)
                if not pkg:
                    continue
                conan = _load_header_map()[pkg]["conan"]
                out.append(InferredDep(conan, None, _conan_purl(conan, None), "conan", CONFIDENCE_C, SOURCE_INCLUDE, [line],
                                       constraint=f"{tool}={version}" if version else None, kind="ci-config"))
        return out

    def _bazel_workspace(self, path: str, rel: str, root: str) -> List[InferredDep]:
        text = _read_text(path)
        if not text:
            return []
        text = re.sub(r"#[^\n]*", "", text)
        out: List[InferredDep] = []
        call = r"\b(http_archive|new_git_repository|git_repository)\s*\(((?:[^()]|\([^()]*\))*)\)"
        for m in re.finditer(call, text):
            kind, body = m.group(1), m.group(2)
            name = re.search(r'\bname\s*=\s*"([^"]+)"', body)
            if not name:
                continue
            line = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
            if kind == "http_archive":
                url = re.search(r'"(https?://[^"]+)"', body)
                prefix = re.search(r'strip_prefix\s*=\s*"([^"]+)"', body)
                ver = None
                for hint in ((prefix.group(1) if prefix else ""), (url.group(1).rsplit("/", 1)[-1] if url else "")):
                    found = _VERSION_RE.search(hint)
                    if found:
                        ver = found.group(0)
                        break
                pkg = known_package(name.group(1))
                if pkg and ver:
                    conan = _load_header_map()[pkg]["conan"]
                    out.append(InferredDep(conan, ver, _conan_purl(conan, ver), "conan", CONFIDENCE_A,
                                           SOURCE_REGISTRY, [line], kind="build-file"))
                else:
                    out.append(InferredDep(name.group(1), ver, _generic_purl(name.group(1), ver,
                                           strip_url_credentials(url.group(1)) if url else None), "generic",
                                           CONFIDENCE_A if ver else CONFIDENCE_C, SOURCE_GIT, [line],
                                           repo_url=strip_url_credentials(url.group(1)) if url else None,
                                           kind="build-file"))
            else:
                remote = re.search(r'remote\s*=\s*"([^"]+)"', body)
                ref = re.search(r'\b(?:tag|commit)\s*=\s*"([^"]+)"', body)
                out.append(self._git_dep(name.group(1), remote.group(1) if remote else None,
                                         ref.group(1) if ref else None, [line], root, "build-file"))
        return out

    def _meson_build(self, path: str, rel: str) -> List[InferredDep]:
        text = _read_text(path)
        if not text:
            return []
        out: List[InferredDep] = []
        for m in re.finditer(r"\bdependency\s*\(\s*'([^']+)'([^)]*)\)", text):
            pkg = known_package(m.group(1))
            if not pkg:
                continue
            constraint = re.search(r"version\s*:\s*'([^']+)'", m.group(2))
            conan = _load_header_map()[pkg]["conan"]
            out.append(InferredDep(conan, None, _conan_purl(conan, None), "conan", CONFIDENCE_C, SOURCE_INCLUDE,
                                   [f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"],
                                   constraint=constraint.group(1) if constraint else None, kind="build-file"))
        return out

    def _autotools(self, path: str, rel: str) -> List[InferredDep]:
        text = _read_text(path)
        if not text:
            return []
        out: List[InferredDep] = []
        for m in re.finditer(r"PKG_CHECK_MODULES\(\s*\[?\w+\]?\s*,\s*\[?\s*([A-Za-z0-9_.+-]+)\s*(?:(>=|=|>)\s*([0-9][0-9.]*))?", text):
            pkg = known_package(m.group(1))
            if not pkg:
                continue
            conan = _load_header_map()[pkg]["conan"]
            line = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
            if m.group(2) == "=" and m.group(3):
                out.append(InferredDep(conan, m.group(3), _conan_purl(conan, m.group(3)), "conan", CONFIDENCE_A,
                                       SOURCE_REGISTRY, [line], kind="build-file"))
            else:
                out.append(InferredDep(conan, None, _conan_purl(conan, None), "conan", CONFIDENCE_C, SOURCE_INCLUDE,
                                       [line], constraint=f"{m.group(2)}{m.group(3)}" if m.group(3) else None,
                                       kind="build-file"))
        return out

    def _meson_wrap(self, path: str, rel: str) -> List[InferredDep]:
        text = _read_text(path, 64_000)
        if not text:
            return []
        name = os.path.splitext(os.path.basename(path))[0]
        directory = re.search(r"^directory\s*=\s*(\S+)", text, re.MULTILINE)
        url = re.search(r"^(?:source_url|url)\s*=\s*(\S+)", text, re.MULTILINE)
        revision = re.search(r"^revision\s*=\s*(\S+)", text, re.MULTILINE)
        version = None
        if directory:
            m = _VERSION_RE.search(directory.group(1))
            version = m.group(0) if m else None
        if not version and revision:
            version = _tag_version(revision.group(1))
        pkg = known_package(name)
        if pkg and version:
            conan = _load_header_map()[pkg]["conan"]
            return [InferredDep(conan, version, _conan_purl(conan, version), "conan", CONFIDENCE_A, SOURCE_REGISTRY, [rel], kind="build-file")]
        return [InferredDep(name, version, _generic_purl(name, version, strip_url_credentials(url.group(1)) if url else None),
                            "generic", CONFIDENCE_A if version else CONFIDENCE_C, SOURCE_GIT, [rel],
                            repo_url=strip_url_credentials(url.group(1)) if url else None, kind="build-file")]

    def _gitmodules(self, root: str) -> List[InferredDep]:
        path = os.path.join(root, ".gitmodules")
        text = _read_text(path, 128_000)
        if not text:
            return []
        out: List[InferredDep] = []
        for block in re.finditer(r'\[submodule\s+"([^"]+)"\]((?:\n[ \t]+[^\n]*)+)', text):
            body = block.group(2)
            sub_path = re.search(r"path\s*=\s*(\S+)", body)
            url = re.search(r"url\s*=\s*(\S+)", body)
            if not sub_path:
                continue
            name = os.path.basename(sub_path.group(1).rstrip("/"))
            sha = self._gitlink_sha(root, sub_path.group(1))
            directory = os.path.join(root, sub_path.group(1))
            out.append(self._git_dep(name, url.group(1) if url else None, sha, [".gitmodules"], root, "submodule", directory))
        return out

    @staticmethod
    def _gitlink_sha(root: str, sub_path: str) -> Optional[str]:
        try:
            done = subprocess.run(["git", "-C", root, "ls-tree", "HEAD", "--", sub_path],
                                  capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        match = re.match(r"160000 commit ([0-9a-f]{40})\t", done.stdout or "")
        return match.group(1) if match else None
