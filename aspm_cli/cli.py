import argparse
import os
from colorama import Fore, init

from aspm_cli.commands import command_registry
from aspm_cli.utils.common import clean_env_vars, print_banner
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.version import get_version

init(autoreset=True)

def main():
    clean_env_vars()
    print_banner()

    parser = argparse.ArgumentParser(prog="accuknox-aspm-scanner", description="ASPM CLI Tool")
    parser.add_argument('--version', action='version', version=f"%(prog)s v{get_version()}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Register all commands from the registry
    for cmd_name, cmd_class in command_registry.items():
        cmd_instance = cmd_class()
        cmd_parser = subparsers.add_parser(cmd_name, help=cmd_instance.help_text)
        cmd_instance.configure_parser(cmd_parser)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        try:
            # Command classes now directly execute via their 'func' attribute set in configure_parser
            args.func(args)
        except Exception as e:
            Logger.get_logger().error(f"Command execution failed: {e}")
            if os.getenv("ASPM_DEBUG"): # Optional: for more detailed debug
                Logger.get_logger().debug("--- Full Traceback ---")
                import traceback
                Logger.get_logger().debug(traceback.format_exc())
            exit(1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()