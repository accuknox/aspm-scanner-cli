import os
from typing import Optional


def resolve_path_within_root(path: str, root: Optional[str] = None) -> str:
    """
    Resolve path and ensure the result stays within root (prevents path traversal).
    Raises ValueError when the resolved path escapes the scan root.
    """
    root = os.path.realpath(root or os.getcwd())
    if not path or path in (".", ""):
        return root

    candidate = path if os.path.isabs(path) else os.path.join(root, path)
    resolved = os.path.realpath(candidate)

    if resolved != root and not resolved.startswith(root + os.sep):
        raise ValueError(
            f"Scan path '{path}' resolves outside the allowed directory '{root}'"
        )
    return resolved
