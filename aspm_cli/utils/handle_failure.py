import os
from colorama import Fore
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.config import SOMETHING_WENT_WRONG_RETURN_CODE, PASS_RETURN_CODE
import sys

def handle_failure(exit_code, soft_fail):
    """Handle pipeline success or failure based on soft fail flag."""
    if exit_code != 0:
        if exit_code == SOMETHING_WENT_WRONG_RETURN_CODE:
            Logger.get_logger().error("")
            sys.exit(1)
        elif exit_code == PASS_RETURN_CODE:
            sys.exit(0)
        elif soft_fail:
            Logger.get_logger().warning("Vulnerabilities detected, but soft fail is enabled. Continuing...")
            sys.exit(0)
        else:
            Logger.get_logger().error("Vulnerabilities detected and soft fail is disabled. Exiting with failure.")
            sys.exit(1)
    else:
        Logger.log_with_color('INFO', "Scan completed successfully.", Fore.GREEN)