import os
import subprocess
from typing import List, Optional

DEFAULT_SCAN_TIMEOUT_SECONDS = 3600


def scan_timeout_seconds() -> Optional[int]:
    """Return subprocess timeout from SCAN_TIMEOUT_SECONDS, or default 1 hour."""
    raw = os.getenv("SCAN_TIMEOUT_SECONDS", "").strip()
    if not raw:
        return DEFAULT_SCAN_TIMEOUT_SECONDS
    try:
        timeout = int(raw)
    except ValueError as exc:
        raise ValueError(
            "SCAN_TIMEOUT_SECONDS must be a positive integer"
        ) from exc
    if timeout <= 0:
        raise ValueError("SCAN_TIMEOUT_SECONDS must be a positive integer")
    return timeout


def run_scan_subprocess(cmd: List[str], **kwargs):
    """Run a scanner subprocess with a configurable timeout."""
    timeout = kwargs.pop("timeout", scan_timeout_seconds())
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        **kwargs,
    )
