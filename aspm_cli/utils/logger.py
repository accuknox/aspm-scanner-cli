import logging
import sys
from colorama import Fore, Style
import os

class Logger:
    _logger = None

    @staticmethod
    def get_logger():
        if Logger._logger is None:
            Logger._logger = logging.getLogger("aspm-cli")
            Logger._logger.setLevel(logging.INFO) # Default to INFO

            # Check if handlers already exist to prevent duplicate messages
            if not Logger._logger.handlers:
                handler = logging.StreamHandler(sys.stdout)
                formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
                handler.setFormatter(formatter)
                Logger._logger.addHandler(handler)

            # Allow environment variable to set debug level
            if os.getenv("ASPM_DEBUG") == "TRUE":
                Logger._logger.setLevel(logging.DEBUG)

        return Logger._logger

    @staticmethod
    def log_with_color(level, message, color):
        logger = Logger.get_logger()
        if level.upper() == 'INFO':
            logger.info(f"{color}{message}{Style.RESET_ALL}")
        elif level.upper() == 'WARNING':
            logger.warning(f"{color}{message}{Style.RESET_ALL}")
        elif level.upper() == 'ERROR':
            logger.error(f"{color}{message}{Style.RESET_ALL}")
        elif level.upper() == 'DEBUG':
            logger.debug(f"{color}{message}{Style.RESET_ALL}")
        else:
            logger.log(logger.level, f"{color}{message}{Style.RESET_ALL}")