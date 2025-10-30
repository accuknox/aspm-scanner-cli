import os
import subprocess
from aspm_cli.utils.logger import Logger
from colorama import Fore

def _run_command(cmd, cwd=None, check=True):
    """Helper to run shell commands."""
    Logger.get_logger().debug(f"Running command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as e:
        Logger.get_logger().error(f"Command failed: {' '.join(cmd)}")
        Logger.get_logger().error(f"Stdout: {e.stdout.strip()}")
        Logger.get_logger().error(f"Stderr: {e.stderr.strip()}")
        raise
    except FileNotFoundError:
        Logger.get_logger().error(f"Command not found: {cmd[0]}. Is it installed and in PATH?")
        raise

def handle_pre_commit(args):
    """
    Handles pre-commit hook installation and uninstallation.
    This function replaces the pre-commit related logic from the original main.py.
    """
    precommit_cmd = args.precommit_cmd
    project_root = os.getcwd() # Assume current directory is the project root

    # Check if pre-commit is installed
    try:
        _run_command(["pre-commit", "--version"], check=True)
    except Exception:
        Logger.get_logger().error(
            f"{Fore.RED}pre-commit is not installed or not in PATH. "
            f"Please install it (e.g., `pip install pre-commit`) and try again.{Fore.RESET}"
        )
        return

    if precommit_cmd == "install":
        Logger.get_logger().info(f"Installing pre-commit hooks in {project_root}...")
        try:
            # This assumes your .pre-commit-config.yaml exists and is configured correctly
            stdout, stderr = _run_command(["pre-commit", "install"], cwd=project_root)
            Logger.log_with_color('INFO', f"Pre-commit hooks installed successfully!\n{stdout}", Fore.GREEN)
        except Exception:
            Logger.get_logger().error(f"{Fore.RED}Failed to install pre-commit hooks.{Fore.RESET}")
            # Optionally show stderr from original command: Logger.get_logger().error(stderr_from_exception)
            # This would require catching CalledProcessError specifically and accessing its stdout/stderr
    elif precommit_cmd == "uninstall":
        Logger.get_logger().info(f"Uninstalling pre-commit hooks from {project_root}...")
        try:
            stdout, stderr = _run_command(["pre-commit", "uninstall"], cwd=project_root)
            Logger.log_with_color('INFO', f"Pre-commit hooks uninstalled successfully!\n{stdout}", Fore.GREEN)
        except Exception:
            Logger.get_logger().error(f"{Fore.RED}Failed to uninstall pre-commit hooks.{Fore.RESET}")
    else:
        # This case should ideally not be reached due to argparse 'required=True'
        Logger.get_logger().error(f"Unknown pre-commit command: {precommit_cmd}")