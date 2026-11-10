"""Incremental scans: resolve the files a PR/branch changed so a scanner can
limit itself to them. Returns None (= scan everything) whenever the diff
can't be trusted, so a failure here never turns into a silent pass."""
import os

from aspm_cli.pr_decorator.detect import detect_pr_context
from aspm_cli.utils.git_info import GitInfo
from aspm_cli.utils.logger import Logger


def is_enabled(args) -> bool:
    return bool(getattr(args, "changed_only", False)) or \
        os.getenv("ACCUKNOX_CHANGED_ONLY", "").lower() in ("1", "true", "yes")


def _ci_base_ref() -> str | None:
    """Base of the PR/MR on CIs detect_pr_context() doesn't cover. Needs the base branch fetched."""
    env = os.environ.get
    if env("ACCUKNOX_BASE_REF"):
        return env("ACCUKNOX_BASE_REF")
    if env("CI_MERGE_REQUEST_DIFF_BASE_SHA"):  # GitLab
        return env("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    branch = (env("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")            # GitLab
              or env("BITBUCKET_PR_DESTINATION_BRANCH")             # Bitbucket
              or (env("SYSTEM_PULLREQUEST_TARGETBRANCH") or "").removeprefix("refs/heads/")  # Azure DevOps
              or env("CHANGE_TARGET"))                              # Jenkins multibranch
    return f"origin/{branch}" if branch else None


def _changed_files(base: str, head: str) -> list[str] | None:
    # ACMR: added/copied/modified/renamed (new name), never deleted. quotepath=false keeps unicode names intact.
    out = GitInfo._run_git_command(["-c", "core.quotepath=false", "diff", "--name-only", "--diff-filter=ACMR", base, head])
    return None if out is None else out.splitlines()


def resolve_changed_files(args) -> list[str] | None:
    """Existing (non-deleted) files changed since the merge-base. [] = nothing
    to scan. None = incremental off or unavailable -> caller does a full scan."""
    if not is_enabled(args):
        return None
    log = Logger.get_logger()
    base, head = getattr(args, "base_ref", None), "HEAD"
    if not base:
        ctx = detect_pr_context()
        if ctx and ctx.base_sha:
            base, head = ctx.base_sha, (ctx.head_sha if ctx.head_sha != "unknown" else "HEAD")
        else:
            base = _ci_base_ref()
    if not base:
        log.warning("--changed-only needs a PR build or --base-ref; running a full scan.")
        return None
    # Diff from the merge-base so changes that landed on the base branch after the PR forked don't count.
    base = GitInfo._run_git_command(["merge-base", base, head]) or base
    files = _changed_files(base, head)
    if files is None:
        log.warning("Could not compute the diff (shallow clone? use fetch-depth: 0); running a full scan.")
        return None
    files = [f for f in files if os.path.isfile(f)]
    limit = int(os.getenv("ACCUKNOX_INCREMENTAL_MAX_FILES", "1000"))
    if len(files) > limit:  # a huge PR gains little from scoping and would overflow the OS argument limit
        log.warning(f"{len(files)} changed files exceed the incremental limit ({limit}); running a full scan.")
        return None
    args.diff_range = f"{base}..{head}"  # for engines that scan git history (gitleaks, trufflehog git)
    log.info(f"Incremental scan: {len(files)} changed file(s) since {base[:12]}.")
    return files


def within(files: list[str], targets: list[str]) -> list[str]:
    """Keep the changed files under any of the scan targets ('.' or no target = all)."""
    roots = [os.path.normpath(t).replace("\\", "/") for t in targets] or ["."]
    if "." in roots:
        return files
    return [f for f in files if any(f == r or f.startswith(r + "/") for r in roots)]


# A change to any of these means the dependency set may differ, so SCA/SBOM re-run in full.
MANIFESTS = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg", "uv.lock",
    "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "gemfile", "gemfile.lock", "cargo.toml", "cargo.lock", "composer.json", "composer.lock",
    "packages.config", "packages.lock.json", "mix.lock", "pubspec.lock", "podfile.lock",
}


def touches_manifest(files: list[str]) -> bool:
    return any(os.path.basename(f).lower() in MANIFESTS
               or f.lower().endswith((".csproj", ".sbom.json", ".cdx.json", ".spdx.json")) for f in files)


# Trufflehog flags that take a value, so the value isn't mistaken for a scan path.
_TH_VALUE_FLAGS = {"--exclude-paths", "--include-paths", "--config", "-c", "--exclude-detectors",
                   "--include-detectors", "--concurrency", "--archive-max-size", "--archive-max-depth",
                   "--archive-timeout", "--results", "--branch", "--since-commit", "--max-depth"}


def scope_trufflehog(tokens: list[str], files: list[str], diff_range: str | None) -> list[str]:
    """filesystem: swap the paths for the changed files. git: only commits since the base."""
    if not tokens:
        return tokens
    if tokens[0] == "filesystem":
        out, targets = [tokens[0]], []
        for i, t in enumerate(tokens[1:], 1):
            if t.startswith("-") or tokens[i - 1] in _TH_VALUE_FLAGS:
                out.append(t)
            else:
                targets.append(t)
        return out + within(files, targets)
    if tokens[0] == "git" and diff_range and "--since-commit" not in tokens:
        return [*tokens, "--since-commit", diff_range.split("..")[0]]
    return tokens


def scope_gitleaks(tokens: list[str], diff_range: str | None) -> list[str]:
    # shortcut: gitleaks can't take a file list; scan the PR's commits only. --no-git scans stay full.
    if diff_range and "--no-git" not in tokens and not any(t.startswith("--log-opts") for t in tokens):
        return [*tokens, f"--log-opts={diff_range}"]
    return tokens


def scope_checkov(tokens: list[str], files: list[str]) -> list[str]:
    """Replace -d/--directory with -f per changed file under it."""
    out, dirs, i = [], [], 0
    while i < len(tokens):
        if tokens[i] in ("-d", "--directory") and i + 1 < len(tokens):
            dirs.append(tokens[i + 1])
            i += 2
            continue
        out.append(tokens[i])
        i += 1
    for f in within(files, dirs):
        out += ["-f", f]
    return out


# Scans that act on repo files; the rest (container, dast, api-discovery, mobile, ml) have no repo diff to scope to.
INCREMENTAL_SCANS = {"sast", "secret", "iac", "sca", "sbom"}
DEPENDENCY_SCANS = {"sca", "sbom"}  # re-run in full, but only when a manifest changed


def should_skip(scan: str, changed: list[str]) -> bool:
    """True when the diff holds nothing this scan can act on."""
    return not (touches_manifest(changed) if scan in DEPENDENCY_SCANS else changed)
