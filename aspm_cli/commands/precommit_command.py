from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.pre_commit_wrapper.config import handle_pre_commit # Assuming this path is correct

class PreCommitCommand(BaseCommand):
    help_text = "Manage pre-commit hooks"

    def configure_parser(self, parser):
        subparsers = parser.add_subparsers(dest="precommit_cmd", required=True)

        install_parser = subparsers.add_parser(
            "install", help="Install pre-commit hooks"
        )
        install_parser.set_defaults(func=self.execute) 

        uninstall_parser = subparsers.add_parser(
            "uninstall", help="Uninstall pre-commit hooks"
        )
        uninstall_parser.set_defaults(func=self.execute)

    def execute(self, args):
        # The original handle_pre_commit already takes 'args' and handles the logic
        handle_pre_commit(args)