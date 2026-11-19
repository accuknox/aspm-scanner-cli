from __future__ import annotations

import subprocess
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.subprocess_utils import utf8_text

class GitInfo:
    """
    Utility class to retrieve Git repository information.
    Handles potential errors gracefully and logs them.
    """
    @staticmethod
    def _run_git_command(command_parts: list[str]) -> str | None:
        try:
            result = subprocess.run(
                ['git'] + command_parts,
                capture_output=True,
                check=True,
                timeout=5,
                **utf8_text(),
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            Logger.get_logger().debug(f"Git command failed: {' '.join(command_parts)} - {e.stderr.strip()}")
            return None
        except FileNotFoundError:
            Logger.get_logger().debug("Git command not found. Is Git installed and in PATH?")
            return None
        except subprocess.TimeoutExpired:
            Logger.get_logger().debug(f"Git command timed out: {' '.join(command_parts)}")
            return None
        except Exception as e:
            Logger.get_logger().debug(f"An unexpected error occurred while running git command: {e}")
            return None

    @staticmethod
    def get_repo_url() -> str | None:
        """Retrieves the Git repository URL."""
        # Try 'origin' remote first, then list all
        url = GitInfo._run_git_command(['config', '--get', 'remote.origin.url'])
        if url:
            return url

        # If origin not found, try to get any remote
        remotes = GitInfo._run_git_command(['remote'])
        if remotes:
            first_remote = remotes.splitlines()[0]
            url = GitInfo._run_git_command(['config', '--get', f'remote.{first_remote}.url'])
            return url
        return None

    @staticmethod
    def get_branch_name() -> str | None:
        """Retrieves the current Git branch name."""
        return GitInfo._run_git_command(['rev-parse', '--abbrev-ref', 'HEAD'])

    @staticmethod
    def get_commit_ref() -> str | None:
        """Retrieves the full commit reference (e.g., HEAD, branch name)."""
        return GitInfo._run_git_command(['rev-parse', '--abbrev-ref', 'HEAD'])

    @staticmethod
    def get_commit_sha() -> str | None:
        """Retrieves the full commit SHA."""
        return GitInfo._run_git_command(['rev-parse', 'HEAD'])

    @staticmethod
    def get_changed_files(base_ref: str, head_ref: str = "HEAD") -> list[str] | None:
        """Files changed between base_ref and head_ref (e.g. a PR's base/head
        SHA), for scoping findings to the diff. None if the diff couldn't be
        computed (e.g. base_ref not fetched - shallow checkout)."""
        out = GitInfo._run_git_command(['diff', '--name-only', base_ref, head_ref])
        return out.splitlines() if out is not None else None

    @staticmethod
    def get_diff_numstat(base_ref: str, head_ref: str = "HEAD") -> list[tuple[str, str, str]] | None:
        """[(path, added, deleted), ...] between base_ref and head_ref, for
        a PR-level changed-files summary. added/deleted are strings ("-" for
        a binary file, per `git diff --numstat`'s own format) - left as-is
        for the caller to render, not coerced to int."""
        out = GitInfo._run_git_command(['diff', '--numstat', base_ref, head_ref])
        if out is None:
            return None
        rows = []
        for line in out.splitlines():
            parts = line.split('\t')
            if len(parts) == 3:
                added, deleted, path = parts
                rows.append((path, added, deleted))
        return rows

    @staticmethod
    def get_unified_diff_for_file(base_ref: str, head_ref: str, path: str) -> str | None:
        """Zero-context unified diff for one file - enough to see which
        lines were added, for lightweight touched-symbol extraction."""
        return GitInfo._run_git_command(['diff', '-U0', base_ref, head_ref, '--', path])