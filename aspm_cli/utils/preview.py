"""Preview features: shipped in the binary but off, and left out of --help, unless ACCUKNOX_PREVIEW=true.

Preview features are not yet stable: their flags, output and behaviour may change in any release.
Currently: incremental scans (--changed-only) and the PR decorator (decorate-pr).
"""
from __future__ import annotations

import argparse
import os
from typing import Mapping

PREVIEW_ENV = "ACCUKNOX_PREVIEW"


def preview_enabled(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return (env.get(PREVIEW_ENV) or "").strip().lower() in ("1", "true", "yes")


def preview_help(text: str) -> str:
    """Help text for a preview option: shown with a [preview] tag when enabled, hidden otherwise."""
    return f"[preview] {text}" if preview_enabled() else argparse.SUPPRESS


def preview_notice(feature: str) -> str:
    return f"{feature} is a preview feature. Set {PREVIEW_ENV}=true to use it."
