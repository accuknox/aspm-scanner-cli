import itertools
import threading
import time
import sys

class Spinner:
    """
    A simple console spinner to indicate ongoing operations.
    """
    def __init__(self, message="Processing...", delay=0.1):
        self.spinner = itertools.cycle(['-', '/', '|', '\\'])
        self.delay = delay
        self.running = False
        self.spinner_thread = None
        self.message = message
        self.prefix = "\r" # For overwriting the line

    def _spin(self):
        while self.running:
            sys.stdout.write(f"{self.prefix}{next(self.spinner)} {self.message}")
            sys.stdout.flush()
            time.sleep(self.delay)

    def start(self):
        if not self.running:
            self.running = True
            self.spinner_thread = threading.Thread(target=self._spin)
            self.spinner_thread.daemon = True # Allow main program to exit even if spinner is running
            self.spinner_thread.start()

    def stop(self, clear_line=True):
        self.running = False
        if self.spinner_thread:
            self.spinner_thread.join()
        if clear_line:
            # Clear the line and move cursor to the beginning
            sys.stdout.write(f"{self.prefix}{' ' * (len(self.message) + 3)}\r")
            sys.stdout.flush()