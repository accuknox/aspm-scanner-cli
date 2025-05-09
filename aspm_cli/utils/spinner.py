import sys
import threading
import itertools
import time
import os
from aspm_cli.utils.logger import Logger
from colorama import Fore, init

init(autoreset=True)


class Spinner:
    def __init__(self, message="Processing...", color=Fore.CYAN):
        self.spinner = itertools.cycle(["|", "/", "-", "\\"])
        self.stop_running = False
        self.message = message
        self.color = color
        self.thread = threading.Thread(target=self._spin)

    def _spin(self):
        # If it's GitHub Actions, use logging instead of spinner
        if os.getenv("GITHUB_ACTIONS") == "true":
            self._log_status()
        else:
            self._use_spinner()

    def _use_spinner(self):
        while not self.stop_running:
            sys.stdout.write(f"\r{self.color}{self.message} {next(self.spinner)}")
            sys.stdout.flush()
            time.sleep(0.1)  

        sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")

    def _log_status(self):
        Logger.get_logger().info(f"{self.message}")
        sys.stdout.flush()

        # Log status update every 10 seconds in GitHub Actions
        last_update = time.time()
        while not self.stop_running:
            if time.time() - last_update >= 10:
                Logger.get_logger().info(f"{self.message} - still processing...")
                sys.stdout.flush()  
                last_update = time.time()

            if self.stop_running:
                Logger.get_logger().info(f"{self.message} - finished processing.")
                sys.stdout.flush()
                break

            time.sleep(1)  # Check for completion every second

    def start(self):
        self.stop_running = False
        self.thread.start()

    def stop(self):
        self.stop_running = True
        self.thread.join()