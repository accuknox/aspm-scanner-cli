"""Embed the conformance result in the exported file itself."""

from __future__ import annotations

from typing import Any, Dict

from .rules import ATTEST_PREFIX
from .validate import attestation_properties


def embed_attestation(doc: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
    """Add the attestation to a CycloneDX or SPDX JSON document (mutates and returns it).

    Re-validating the result gives the same status, because the attestation
    properties are not themselves counted as data fields.
    """
    props = attestation_properties(report)
    if doc.get("bomFormat") == "CycloneDX":
        md = doc.setdefault("metadata", {})
        existing = [p for p in md.get("properties", []) if not str(p.get("name", "")).startswith(ATTEST_PREFIX)]
        md["properties"] = existing + [{"name": ATTEST_PREFIX + k, "value": v} for k, v in props.items()]
    else:
        ci = doc["creationInfo"]
        tool = ci["creators"][0] if ci.get("creators") else "Tool: AccuKnox"
        date = ci["created"]
        kept = [a for a in doc.get("annotations", []) if not a.get("comment", "").startswith(ATTEST_PREFIX)]
        doc["annotations"] = kept + [
            {
                "annotationType": "OTHER",
                "annotator": tool,
                "annotationDate": date,
                "comment": "{}{}={}".format(ATTEST_PREFIX, k, v),
            }
            for k, v in props.items()
        ]
        ci["comment"] = "CERT-In SBOM data-field check: {} ({})".format(report["status"], report["profile"])
    return doc
