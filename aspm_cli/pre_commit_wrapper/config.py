from pre_commit.commands.install_uninstall import install, uninstall
from pre_commit.store import Store
from pre_commit import git
from pre_commit.constants import CONFIG_FILE
import os
import subprocess
from pathlib import Path

PRE_COMMIT_CONTENT = """repos:
  - repo: local
    hooks:
      - id: accuknox-secret-scan
        name: AccuKnox Secret Scan
        entry:  accuknox-aspm-scanner scan --skip-upload secret --command "git file://." --container-mode
        language: system
        stages: [pre-commit]
        types: [text]
        pass_filenames: false
"""

GLOBAL_HOOKS_DIR = Path.home() / ".accuknox" / "git-hooks"
GLOBAL_HOOK_FILE = GLOBAL_HOOKS_DIR / "pre-commit"
GLOBAL_BACKUP_FILE = GLOBAL_HOOKS_DIR / ".core.hooksPath.bak"

GLOBAL_HOOK_SCRIPT = """#!/usr/bin/env bash
set -euo pipefail

# AccuKnox Secret Scan (global pre-commit hook)
# Runs in the context of the current repository.
accuknox-aspm-scanner scan --skip-upload secret --command "git file://." --container-mode
"""

def _git_config_global_get(key: str) -> str:
    result = subprocess.run(
        ["git", "config", "--global", "--get", key],
        capture_output=True,
        text=True,
        check=False,
    )
    return (result.stdout or "").strip()

def _git_config_global_set(key: str, value: str) -> None:
    subprocess.run(["git", "config", "--global", key, value], check=False)

def _git_config_global_unset(key: str) -> None:
    subprocess.run(["git", "config", "--global", "--unset", key], check=False)

def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o755)

def _install_global_hook() -> int:
    # Backup existing hooksPath, if any
    existing = _git_config_global_get("core.hooksPath")
    GLOBAL_HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    if existing:
        GLOBAL_BACKUP_FILE.write_text(existing)
    else:
        # clear any previous backup so uninstall doesn't restore stale values
        if GLOBAL_BACKUP_FILE.exists():
            GLOBAL_BACKUP_FILE.unlink()

    _write_executable(GLOBAL_HOOK_FILE, GLOBAL_HOOK_SCRIPT)
    _git_config_global_set("core.hooksPath", str(GLOBAL_HOOKS_DIR))
    return 0

def _uninstall_global_hook() -> int:
    # Restore previous hooksPath if we have a backup, else unset.
    if GLOBAL_BACKUP_FILE.exists():
        previous = GLOBAL_BACKUP_FILE.read_text().strip()
        if previous:
            _git_config_global_set("core.hooksPath", previous)
        else:
            _git_config_global_unset("core.hooksPath")
        GLOBAL_BACKUP_FILE.unlink(missing_ok=True)
    else:
        _git_config_global_unset("core.hooksPath")

    # Remove hook script
    if GLOBAL_HOOK_FILE.exists():
        GLOBAL_HOOK_FILE.unlink()
    return 0

# TODO: display the findings, remove results.json file
def handle_pre_commit(args):

    try:
        store = Store()
        git.check_for_cygwin_mismatch()

        if args.precommit_cmd == "install":
            if getattr(args, "global_install", False):
                exit_code = _install_global_hook()
            else:
                # create .pre-commit-config.yaml
                with open(CONFIG_FILE, "w") as f:
                    f.write(PRE_COMMIT_CONTENT)
                exit_code = install(
                    CONFIG_FILE,
                    store,
                    hook_types=None,
                    overwrite=True,
                    hooks=True,
                )
        elif args.precommit_cmd == "uninstall":
            if getattr(args, "global_install", False):
                exit_code = _uninstall_global_hook()
            else:
                exit_code = uninstall(config_file=CONFIG_FILE, hook_types=None)
        else:
            exit_code = 1

    except Exception as e:
        print(f"Pre-commit failed: {e}")