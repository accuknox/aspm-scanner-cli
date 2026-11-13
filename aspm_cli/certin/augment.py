"""Add the CERT-In fields to an existing scanner SBOM in place.

Unlike the exporters (which rebuild a document from the platform's graph), this
keeps every byte the scanner wrote and only adds: document author, timestamp,
lifecycle and level, per-component ``certin:`` properties (or SPDX annotations),
declared unknowns, and the conformance attestation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .attest import embed_attestation
from .build import component_properties, derive_all, now_iso
from .export_cyclonedx import LIFECYCLE_PHASE
from .read_model import model_from_cyclonedx, model_from_spdx
from .rules import PROPERTY_PREFIX
from .validate import validate_document


SUPPLIER_SOURCE = PROPERTY_PREFIX + "supplier-source"
_FORGES = ("github.com", "gitlab.com", "bitbucket.org")


def supplier_from_purl(purl: str) -> Optional[str]:
    """The organisation a package URL's namespace names, where the namespace really is one.

    Maven group ids, npm scopes and forge owners (github.com/<owner>/...) name who publishes the package.
    Other ecosystems have no such namespace, and a distribution name (pkg:deb/debian/...) is not a supplier
    the scanner can vouch for, so those return None and the field stays declared unknown.
    """
    text = str(purl).split("#", 1)[0].split("?", 1)[0]
    if not text.startswith("pkg:"):
        return None
    kind, _, rest = text[4:].partition("/")
    parts = rest.rpartition("@")[0].split("/") if "@" in rest.split("/")[-1] else rest.split("/")
    namespace = parts[:-1]
    if not namespace:
        return None
    if kind == "maven":
        return namespace[0]
    if kind == "npm":
        scope = namespace[0].replace("%40", "@")
        return scope.lstrip("@") if scope.startswith("@") else None
    if kind in ("github", "gitlab", "bitbucket"):
        return namespace[0]
    if kind == "golang" and len(namespace) >= 2 and namespace[0].lower() in _FORGES:
        return namespace[1]
    return None


def _fill_suppliers(doc: Dict[str, Any]) -> None:
    """Give components that name no supplier the one their package URL implies, and say so in a property."""
    for comp in doc.get("components", []) or []:
        if not isinstance(comp, dict) or comp.get("supplier") or comp.get("publisher") or not comp.get("purl"):
            continue
        name = supplier_from_purl(comp["purl"])
        if not name:
            continue
        comp["supplier"] = {"name": name}
        props = [p for p in comp.get("properties", []) if p.get("name") != SUPPLIER_SOURCE]
        comp["properties"] = props + [{"name": SUPPLIER_SOURCE, "value": "purl-namespace"}]


def _stamp_cyclonedx(
    doc: Dict[str, Any], author: Optional[str], lifecycle: str, level: str, bom_version: Optional[int] = None
) -> None:
    if bom_version:
        doc["version"] = int(bom_version)
    md = doc.setdefault("metadata", {})
    md.setdefault("timestamp", now_iso())
    if author and not md.get("authors"):
        md["authors"] = [{"name": author}]
    if lifecycle in LIFECYCLE_PHASE:
        md.setdefault("lifecycles", [{"phase": LIFECYCLE_PHASE[lifecycle]}])
    props = [
        p
        for p in md.get("properties", [])
        if not str(p.get("name", "")).startswith((PROPERTY_PREFIX + "lifecycle", PROPERTY_PREFIX + "sbom-level"))
    ]
    if lifecycle:
        props.append({"name": PROPERTY_PREFIX + "lifecycle", "value": lifecycle})
    if level:
        props.append({"name": PROPERTY_PREFIX + "sbom-level", "value": level})
    md["properties"] = props


def augment_cyclonedx(
    doc: Dict[str, Any],
    author: Optional[str] = None,
    lifecycle: str = "",
    level: str = "",
    bom_version: Optional[int] = None,
) -> Dict[str, Any]:
    """Mutate a CycloneDX document and return its conformance report.

    ``bom_version`` sets the document's revision number (CycloneDX ``version``); without it the
    scanner's own value stays.
    """
    _stamp_cyclonedx(doc, author, lifecycle, level, bom_version)
    _fill_suppliers(doc)
    model = model_from_cyclonedx(doc)
    derived = derive_all(model)
    raw: List[Dict[str, Any]] = (
        [doc["metadata"]["component"]] if isinstance(doc["metadata"].get("component"), dict) else []
    ) + [c for c in doc.get("components", []) if isinstance(c, dict)]
    by_ref = {
        c.get("bom-ref") or c.get("purl") or "{}@{}".format(c.get("name", ""), c.get("version", "")): c for c in raw
    }
    for ref, fields in derived.items():
        comp = by_ref.get(ref)
        if comp is None:
            continue
        kept = [
            p
            for p in comp.get("properties", [])
            if not str(p.get("name", "")).startswith(PROPERTY_PREFIX) or p.get("name") == SUPPLIER_SOURCE
        ]
        comp["properties"] = kept + [{"name": PROPERTY_PREFIX + k, "value": v} for k, v in component_properties(fields)]
        if not comp.get("bom-ref"):
            comp["bom-ref"] = ref
    if not model.meta.has_nested_dependencies and model.components:
        root_ref = model.root.ref if model.root else None
        # A flat graph says nothing about what each library depends on: keep the root's
        # edges, drop the empty per-library entries, and say the rest is unknown.
        doc["dependencies"] = [d for d in doc.get("dependencies", []) if d.get("ref") == root_ref or d.get("dependsOn")]
        doc["compositions"] = [c for c in doc.get("compositions", []) if c.get("aggregate") != "unknown"] + [
            {"aggregate": "unknown", "dependencies": [c.ref for c in model.components]}
        ]
    report = validate_document(doc)
    embed_attestation(doc, report)
    return report


def augment_spdx(
    doc: Dict[str, Any], author: Optional[str] = None, lifecycle: str = "", level: str = ""
) -> Dict[str, Any]:
    ci = doc.setdefault("creationInfo", {"creators": []})
    ci.setdefault("created", now_iso())
    creators = ci.setdefault("creators", [])
    # A scanner lists itself or its vendor as "Organization:"; that is not who authored the SBOM data.
    if author and not any(c.startswith("Person:") for c in creators):
        creators.append("Person: " + author)
    tool = next((c for c in creators if c.startswith("Tool:")), "Tool: AccuKnox")
    created = ci["created"]

    def note(text: str) -> Dict[str, str]:
        return {"annotationType": "OTHER", "annotator": tool, "annotationDate": created, "comment": text}

    doc_notes = [
        a
        for a in doc.get("annotations", [])
        if not a.get("comment", "").startswith((PROPERTY_PREFIX + "lifecycle", PROPERTY_PREFIX + "sbom-level"))
    ]
    if lifecycle:
        doc_notes.append(note("{}lifecycle={}".format(PROPERTY_PREFIX, lifecycle)))
    if level:
        doc_notes.append(note("{}sbom-level={}".format(PROPERTY_PREFIX, level)))
    doc["annotations"] = doc_notes

    model = model_from_spdx(doc)
    derived = derive_all(model)
    ids = {p.get("SPDXID", p.get("name")): p for p in doc.get("packages", [])}
    for ref, fields in derived.items():
        pkg = ids.get(ref)
        if pkg is None:
            continue
        kept = [a for a in pkg.get("annotations", []) if not a.get("comment", "").startswith(PROPERTY_PREFIX)]
        pkg["annotations"] = kept + [
            note("{}{}={}".format(PROPERTY_PREFIX, k, v)) for k, v in component_properties(fields)
        ]
    if not model.meta.has_nested_dependencies and model.components:
        doc["annotations"].append(note(PROPERTY_PREFIX + "unknown:dependency-graph=flat-dependency-graph"))
    report = validate_document(doc)
    embed_attestation(doc, report)
    return report
