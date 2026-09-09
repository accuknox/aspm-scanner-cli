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


def utf8_text(**kwargs):
    """Text-mode subprocess kwargs that stay UTF-8 on Windows.

    ``text=True`` alone uses the locale encoding (often cp1252/'charmap' on
    Windows), which raises UnicodeDecodeError on OpenGrep/CodeAssure output.
    """
    merged = {"text": True, "encoding": "utf-8", "errors": "replace"}
    merged.update(kwargs)
    return merged


def run_scan_subprocess(cmd: List[str], **kwargs):
    """Run a scanner subprocess with a configurable timeout."""
    timeout = kwargs.pop("timeout", scan_timeout_seconds())
    return subprocess.run(
        cmd,
        capture_output=True,
        timeout=timeout,
        **utf8_text(**kwargs),
    )
