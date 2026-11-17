"""Temporary, tree-external manifests built from inferred dependencies."""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
from typing import Iterator, List, Optional

from aspm_cli.inference.base import InferredDep

OVERLAY_LOCK_NAME = "conan.lock"


def render_conan_lock(deps: List[InferredDep]) -> str:
    """A Conan lockfile naming every dependency whose version could be resolved."""
    requires = sorted({f"{d.name}/{d.version}" for d in deps if d.lookup_eligible and d.ecosystem == "conan"})
    return json.dumps({"version": "0.5", "requires": requires, "build_requires": [], "python_requires": []}, indent=2)


@contextlib.contextmanager
def inferred_overlay(deps: List[InferredDep]) -> Iterator[Optional[str]]:
    """Yield a temp directory holding a synthetic ``conan.lock`` (or None when nothing is eligible).

    The directory is created outside the scanned tree and removed on exit.
    """
    if not any(d.lookup_eligible and d.ecosystem == "conan" for d in deps):
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="accuknox-inferred-") as tmp:
        with open(os.path.join(tmp, OVERLAY_LOCK_NAME), "w", encoding="utf-8") as handle:
            handle.write(render_conan_lock(deps))
        yield tmp
