from abc import ABC, abstractmethod
import argparse

from aspm_cli.utils.config import ConfigValidator

class BaseScanner(ABC):
    """
    Abstract Base Class for all scanner strategies.
    Defines the interface for adding command-line arguments,
    validating scanner-specific configurations, and running the scan.
    """
    help_text = "Base scanner help text."
    data_type_identifier = "UNKNOWN" # To be overridden by concrete scanners

    def __init__(self):
        # Placeholder for common scanner initialization if needed
        pass

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser):
        """
        Adds scanner-specific arguments to the provided argparse subparser.
        """
        pass

    @abstractmethod
    def validate_config(self, args: argparse.Namespace, validator: ConfigValidator):
        """
        Validates scanner-specific configurations using the ConfigValidator.
        """
        pass

    @abstractmethod
    def run_scan(self, args: argparse.Namespace) -> tuple[int, str]:
        """
        Executes the specific scan and returns an exit code and a path to the result file.
        Returns: (exit_code, result_file_path)
        """
        pass