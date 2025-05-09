import logging
import os
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

class Logger:
    _instance = None
    _default_colors = {
        'INFO': Fore.BLUE,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED
    }
    
    @classmethod
    def get_logger(cls):
        if not cls._instance:
            cls._instance = cls._initialize_logger()
        return cls._instance
    
    @classmethod
    def _initialize_logger(cls):
        logger = logging.getLogger(__name__)

        # Avoid reconfiguring logging if already configured
        if not logger.hasHandlers():
            # Set log level based on environment variable
            logger.setLevel(logging.DEBUG if os.getenv('DEBUG', 'FALSE').upper() == 'TRUE' else logging.INFO)
            
            # Add StreamHandler with colored formatter
            formatter = cls._get_colored_formatter()
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        return logger

    @classmethod
    def _get_colored_formatter(cls):
        # Custom formatter that adds color to the log level
        log_format = '%(asctime)s - %(levelname)s - %(message)s'

        class ColoredFormatter(logging.Formatter):
            def format(self, record):
                log_message = super().format(record)
                # Apply color formatting based on log level
                if record.levelname == 'ERROR':
                    return Fore.RED + log_message
                elif record.levelname == 'WARNING':
                    return Fore.YELLOW + log_message
                elif record.levelname == 'INFO':
                    return Fore.BLUE + log_message
                return log_message
        
        return ColoredFormatter(log_format)
    
    @staticmethod
    def log_with_color(level, message, color=None):
        # Get the logger
        logger = Logger.get_logger()

        # If a custom color is passed, apply it to the message
        if color:
            message = color + message

        # Log the message with the specified level
        if level == 'INFO':
            logger.info(message)
        elif level == 'WARNING':
            logger.warning(message)
        elif level == 'ERROR':
            logger.error(message)
        else:
            logger.debug(message)  # Default to DEBUG if level is not recognized

