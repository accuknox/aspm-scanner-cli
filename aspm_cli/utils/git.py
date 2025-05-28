import subprocess
import os
import re

class GitInfo:
    @staticmethod
    def get_repo_url():
        """Returns the repository URL, removing any credentials if present."""
        try:
            repo_url = subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            
            # Remove credentials from the URL, e.g., https://username:token@domain/repo
            clean_url = re.sub(r'https?://[^@]+@', 'https://', repo_url)
            
            return clean_url
        except subprocess.CalledProcessError:
            return None
        
    @staticmethod
    def get_branch_name():
        """Returns the current branch name (e.g., 'main', 'develop')."""
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL
            ).decode().strip()
        except subprocess.CalledProcessError:
            return None

    @staticmethod
    def get_commit_sha():
        """Returns the commit SHA (full hash) of the current commit."""
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL
            ).decode().strip()
        except subprocess.CalledProcessError:
            return None

    def get_commit_ref():
        """
        Returns the current commit reference, such as 'refs/heads/main' or short commit hash if in detached HEAD.
        """
        try:
            # Try to get the symbolic ref (e.g., refs/heads/main)
            return subprocess.check_output(
                ["git", "symbolic-ref", "-q", "HEAD"],
                stderr=subprocess.DEVNULL
            ).decode().strip()
        except subprocess.CalledProcessError:
            try:
                # If that fails (detached HEAD), fall back to branch name
                return GitInfo.get_branch_name()
            except subprocess.CalledProcessError:
                return None

    @staticmethod
    def get_repository_name():
        """Returns the repository name from the URL."""
        try:
            repo_url = GitInfo.get_repo_url()
            if repo_url:
                return os.path.basename(repo_url).replace(".git", "")
            return None
        except Exception:
            return None
