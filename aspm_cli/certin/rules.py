"""CERT-In SBOM rule table and shared constants.

Pure Python (3.9+), no Django: this package is also vendored into the scanner
CLI, so it must not import anything outside the standard library.
"""

from __future__ import annotations

from typing import Any, Dict, List

import json
import os
from functools import lru_cache

NOASSERTION = "NOASSERTION"
PROPERTY_PREFIX = "certin:"
UNKNOWN_PREFIX = PROPERTY_PREFIX + "unknown:"
ATTEST_PREFIX = "accuknox:cert-in:"

# Field ids, in guideline order (4.2.1 .. 4.2.21).
FIELD_IDS = (
    "component_name",
    "component_version",
    "component_description",
    "component_supplier",
    "component_license",
    "component_origin",
    "component_dependencies",
    "vulnerabilities",
    "patch_status",
    "release_date",
    "end_of_life_date",
    "criticality",
    "usage_restrictions",
    "checksums",
    "comments",
    "sbom_author",
    "timestamp",
    "executable_property",
    "archive_property",
    "structured_property",
    "unique_identifier",
)

# Field states. ``present`` and ``derived`` are populated; ``declared_unknown`` is
# an explicit NOASSERTION plus reason; ``missing`` is neither.
PRESENT = "present"
DERIVED = "derived"
DECLARED_UNKNOWN = "declared_unknown"
MISSING = "missing"
POPULATED_STATES = (PRESENT, DERIVED)

CONFORMANT = "conformant"
PARTIAL = "partially_conformant"
NON_CONFORMANT = "non_conformant"


@lru_cache(maxsize=1)
def load_rules() -> Dict[str, Any]:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert_in_rules.json")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def component_fields() -> List[Dict[str, Any]]:
    """Rules that apply per component (everything not document-scoped)."""
    return [f for f in load_rules()["fields"] if f.get("scope") != "document"]


def document_fields() -> List[Dict[str, Any]]:
    return [f for f in load_rules()["fields"] if f.get("scope") == "document"]
