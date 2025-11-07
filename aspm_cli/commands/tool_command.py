import os
import sys
from colorama import Fore
from pydantic import ValidationError

from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.tool.download import ToolDownloader
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.spinner import Spinner
from aspm_cli.utils.validation import ALLOWED_TOOL_TYPES, ToolDownloadConfig

class ToolCommand(BaseCommand):
    help_text = "Manage internal tools (install/update)"

    def configure_parser(self, parser):
        subparsers = parser.add_subparsers(dest="toolcmd", required=True)

        # tool install
        tool_install_parser = subparsers.add_parser("install", help="Install a specific tool or all tools")
        self._add_download_args(tool_install_parser)
        tool_install_parser.set_defaults(func=self.execute, mode="install")

        # tool update
        tool_update_parser = subparsers.add_parser("update", help="Update a specific tool or all tools")
        self._add_download_args(tool_update_parser)
        tool_update_parser.set_defaults(func=self.execute, mode="update")

    def _add_download_args(self, subparser):
        group = subparser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "--all",
            action="store_true",
            help="Install/update all tools"
        )
        group.add_argument(
            "--type",
            choices=ALLOWED_TOOL_TYPES,
            help=f"Tool to install/update (choices: {', '.join(ALLOWED_TOOL_TYPES)})"
        )

    def execute(self, args):
        try:
            validated = ToolDownloadConfig(tooltype=args.type, all=args.all)
        except ValidationError as e:
            Logger.get_logger().error(str(e))
            sys.exit(1)

        downloader = ToolDownloader()
        overwrite = args.mode == "update"
        action_message = {"install": "installed", "update": "updated"}
        action_message_present = {"install": "Installing", "update": "Updating"}

        if validated.all:
            for tool in ALLOWED_TOOL_TYPES:
                spinner = Spinner(message=f"{action_message_present[args.mode]} tool for: {tool}")
                spinner.start()
                downloaded = downloader.download_tool(tool, overwrite)  # <-- FIXED HERE
                spinner.stop()
                if downloaded:
                    Logger.log_with_color(
                        'INFO',
                        f"{tool} {action_message[args.mode]} successfully.",
                        Fore.GREEN
                    )
        else:
            spinner = Spinner(message=f"{action_message_present[args.mode]} tool for: {validated.tooltype}")
            spinner.start()
            downloaded = downloader.download_tool(validated.tooltype, overwrite)
            spinner.stop()
            if downloaded:
                Logger.log_with_color(
                    'INFO',
                    f"{validated.tooltype} {action_message[args.mode]} successfully.",
                    Fore.GREEN
                )