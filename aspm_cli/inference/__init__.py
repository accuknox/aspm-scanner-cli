"""Source-based dependency inference for trees that lack a dependency tracker."""
from __future__ import annotations

from typing import List, Optional, Set

from aspm_cli.inference.base import InferenceResult, InferredDep, LanguageInferrer
from aspm_cli.inference.cpp import CppInferrer

INFERRERS: List[LanguageInferrer] = [CppInferrer()]


def infer_dependencies(root: str, existing_names: Optional[Set[str]] = None) -> InferenceResult:
    """Run every registered inferrer whose language is present in ``root`` and combine the results."""
    combined = InferenceResult()
    for inferrer in INFERRERS:
        if not inferrer.detect(root):
            continue
        part = inferrer.infer(root, existing_names)
        combined.deps.extend(part.deps)
        combined.files_scanned += part.files_scanned
        for header, count in part.unresolved_includes.items():
            combined.unresolved_includes[header] = combined.unresolved_includes.get(header, 0) + count
    return combined


__all__ = ["INFERRERS", "InferenceResult", "InferredDep", "infer_dependencies"]
