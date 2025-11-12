import os
import sys
import itertools
import asyncio
import threading
from aspm_cli.utils.logger import Logger
from colorama import Fore, init

init(autoreset=True)


class Spinner:
    def __init__(self, message="Processing...", color=Fore.GREEN):
        self.message = message
        self.color = color
        # GITHUB_ACTIONS / TF_BUILD-AzureDevOps Auto detect
        self.is_ci = os.getenv('DISABLE_SPINNER', 'FALSE').upper() == 'TRUE' or os.getenv("GITHUB_ACTIONS") == "true" or os.getenv("TF_BUILD") == "True"
        self._running = False
        self._spinner = itertools.cycle(["|", "/", "-", "\\"])
        self._loop = None
        self._thread = None
        self._task = None

    def start(self):
        if self.is_ci:
            Logger.get_logger().info(self.message)
        else:
            self._running = True
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._start_async_loop, daemon=True)
            self._thread.start()

    def stop(self):
        if self.is_ci:
            Logger.get_logger().info(f"{self.color}{self.message} - finished processing.")
        else:
            self._running = False

            if self._loop and self._loop.is_running():
                fut = asyncio.run_coroutine_threadsafe(self._cleanup(), self._loop)
                fut.result()

                self._loop.call_soon_threadsafe(self._loop.stop)
                self._thread.join()

            sys.stdout.write("\r" + " " * (len(self.message) + 4) + "\r\n")
            sys.stdout.flush()

    async def _cleanup(self):
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def _start_async_loop(self):
        asyncio.set_event_loop(self._loop)
        self._task = self._loop.create_task(self._spinner_loop())
        self._loop.run_forever()

    async def _spinner_loop(self):
        while self._running:
            char = next(self._spinner)
            sys.stdout.write(f"\r{self.color}{self.message} {char}")
            sys.stdout.flush()
            await asyncio.sleep(0.1)