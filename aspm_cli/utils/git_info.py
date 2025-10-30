import subprocess
from aspm_cli.utils.logger import Logger

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
                text=True,
                check=True,
                timeout=5
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