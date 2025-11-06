from abc import ABC, abstractmethod

class BaseCommand(ABC):
    """
    Abstract Base Class for all CLI commands.
    Defines the interface for configuring argument parsers and executing commands.
    """
    help_text = "Base command help text."

    @abstractmethod
    def configure_parser(self, parser):
        """
        Configures the argparse subparser for this command.
        This method should add all command-specific arguments and set the default function to self.execute.
        """
        pass

    @abstractmethod
    def execute(self, args):
        """
        Executes the logic for this command based on the parsed arguments.
        """
        pass