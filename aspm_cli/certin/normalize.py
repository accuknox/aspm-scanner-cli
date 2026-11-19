"""Read a CycloneDX or SPDX document back into per-field states.

This is what makes the check work on the *file* (the only thing a recipient
holds), so the CLI, the platform and a customer all run the same code over the
same bytes. It understands our own ``certin:`` properties and annotations plus
the standard slots of both formats, so a third-party SBOM is judged on what it
actually says.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import json
import re
from dataclasses import dataclass, field

from .derive import FieldValue, unknown
from .rules import ATTEST_PREFIX, DECLARED_UNKNOWN, MISSING, NOASSERTION, PRESENT, PROPERTY_PREFIX, load_rules

SDOC = "SPDX"
CDX = "CycloneDX"


@dataclass
class NormComponent:
    ref: str
    name: str
    fields: Dict[str, FieldValue] = field(default_factory=dict)
    is_root: bool = False


@dataclass
class NormDoc:
    format: str
    spec_version: str
    document: Dict[str, FieldValue]
    components: List[NormComponent]
    profile: str = "full"
    notes: List[str] = field(default_factory=list)
    lifecycle: str = ""
    level: str = ""
    attestation: Dict[str, str] = field(default_factory=dict)


def _present(value: Any, source: str = "sbom") -> FieldValue:
    return FieldValue(value, PRESENT, source=source)


def _missing(reason: str = "") -> FieldValue:
    return FieldValue(None, MISSING, reason=reason)


def _check_vocab(rule_id: str, value: str) -> FieldValue:
    vocab = load_rules()["vocabularies"]
    text = (value or "").strip()
    if rule_id == "criticality":
        return _present(text) if text.lower() in vocab["criticality"] else _missing("invalid-value")
    if rule_id == "component_origin":
        return _present(text) if text.lower() in vocab["origin"] else _missing("invalid-value")
    if rule_id in ("executable_property", "archive_property", "structured_property"):
        return _present(text) if re.match(r"^(yes|no)\b", text, re.IGNORECASE) else _missing("invalid-value")
    return _present(text)


_PROP_TO_RULE = {
    "origin": "component_origin",
    "patch-status": "patch_status",
    "criticality": "criticality",
    "usage-restrictions": "usage_restrictions",
    "executable": "executable_property",
    "archive": "archive_property",
    "structured": "structured_property",
    "unique-id": "unique_identifier",
    "release-date": "release_date",
    "end-of-life-date": "end_of_life_date",
}


def _apply_properties(fields: Dict[str, FieldValue], props: List[Tuple[str, str]]) -> None:
    for name, value in props:
        if not name.startswith(PROPERTY_PREFIX):
            continue
        key = name[len(PROPERTY_PREFIX) :]
        if key.startswith("unknown:"):
            rule_id = key[len("unknown:") :]
            # A marker never overrides a populated value, but gives a declared unknown its specific reason.
            if rule_id not in fields or fields[rule_id].state in (MISSING, DECLARED_UNKNOWN):
                fields[rule_id] = unknown(value or "unspecified")
        elif key in _PROP_TO_RULE:
            rule_id = _PROP_TO_RULE[key]
            fields[rule_id] = _check_vocab(rule_id, value)


# ── CycloneDX ───────────────────────────────────────────────────────────────


def _cdx_licenses(entries: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for e in entries or []:
        if "expression" in e:
            out.append(e["expression"])
        elif isinstance(e.get("license"), dict):
            out.append(e["license"].get("id") or e["license"].get("name") or "")
    return [x for x in out if x]


def _cdx_component(
    comp: Dict[str, Any],
    deps: Dict[str, List[str]],
    unknown_dep_refs: set,
    vuln_refs: set,
    vuln_analysis: bool,
    is_root: bool,
) -> NormComponent:
    ref = comp.get("bom-ref") or comp.get("name", "")
    f: Dict[str, FieldValue] = {}
    f["component_name"] = _present(comp["name"]) if comp.get("name") else _missing()
    f["component_version"] = _present(comp["version"]) if comp.get("version") else _missing()
    if comp.get("description"):
        f["component_description"] = _present(comp["description"])
    supplier = (comp.get("supplier") or {}).get("name") or comp.get("publisher")
    if supplier:
        f["component_supplier"] = _present(supplier)
    lics = _cdx_licenses(comp.get("licenses", []))
    if lics:
        f["component_license"] = _present(lics)
    hashes = [h for h in comp.get("hashes", []) if h.get("alg") and h.get("content")]
    if hashes:
        f["checksums"] = _present(hashes)
    if ref in deps:
        f["component_dependencies"] = _present(deps[ref])
    elif ref in unknown_dep_refs:
        f["component_dependencies"] = unknown("composition-unknown")
    if ref in vuln_refs:
        f["vulnerabilities"] = _present([ref])
    elif vuln_analysis:
        f["vulnerabilities"] = _present([])
    _apply_properties(
        f, [(p.get("name", ""), p.get("value", "")) for p in comp.get("properties", []) if isinstance(p, dict)]
    )
    for rule in load_rules()["fields"]:
        f.setdefault(rule["id"], _missing())
    return NormComponent(ref=ref, name=comp.get("name", ""), fields=f, is_root=is_root)


def normalize_cyclonedx(doc: Dict[str, Any]) -> NormDoc:
    md = doc.get("metadata") or {}
    deps = {d["ref"]: list(d.get("dependsOn", [])) for d in doc.get("dependencies", []) if d.get("ref")}
    unknown_dep_refs = {
        ref
        for comp in doc.get("compositions", [])
        if comp.get("aggregate") in ("unknown", "not_specified")
        for ref in comp.get("dependencies", []) + comp.get("assemblies", [])
    }
    vulns = doc.get("vulnerabilities")
    vuln_refs = {a.get("ref") for v in vulns or [] for a in v.get("affects", [])}
    props = [(p.get("name", ""), p.get("value", "")) for p in md.get("properties", []) if isinstance(p, dict)]
    prop_map = dict(props)

    document: Dict[str, FieldValue] = {}
    authors = [a.get("name") for a in md.get("authors", []) if a.get("name")]
    if md.get("manufacturer", {}).get("name"):
        authors.append(md["manufacturer"]["name"])
    document["sbom_author"] = _present(authors) if authors else _missing()
    document["timestamp"] = _present(md["timestamp"]) if md.get("timestamp") else _missing()

    components: List[NormComponent] = []
    root = md.get("component")
    if isinstance(root, dict) and root.get("name"):
        components.append(_cdx_component(root, deps, unknown_dep_refs, vuln_refs, vulns is not None, True))
    for comp in doc.get("components", []):
        if isinstance(comp, dict) and comp.get("name"):
            components.append(_cdx_component(comp, deps, unknown_dep_refs, vuln_refs, vulns is not None, False))
    lifecycles = [l.get("phase") for l in md.get("lifecycles", []) if isinstance(l, dict)]
    return NormDoc(
        format=CDX,
        spec_version=str(doc.get("specVersion", "")),
        document=document,
        components=components,
        profile=prop_map.get(PROPERTY_PREFIX + "profile", "full"),
        lifecycle=prop_map.get(PROPERTY_PREFIX + "lifecycle", lifecycles[0] if lifecycles else ""),
        level=prop_map.get(PROPERTY_PREFIX + "sbom-level", ""),
        attestation={k[len(ATTEST_PREFIX) :]: v for k, v in props if k.startswith(ATTEST_PREFIX)},
    )


# ── SPDX ────────────────────────────────────────────────────────────────────


def _spdx_annotation_props(annotations: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for a in annotations or []:
        comment = a.get("comment", "")
        if "=" in comment:
            key, _, value = comment.partition("=")
            out.append((key, value))
    return out


def _spdx_value(text: Optional[str]) -> Optional[str]:
    if text is None or text in ("", "NONE"):
        return None
    return text


def _spdx_component(
    pkg: Dict[str, Any],
    dep_map: Dict[str, List[str]],
    dep_state: str,
    vuln_analysis: bool,
    ids: Dict[str, str],
    is_root: bool,
) -> NormComponent:
    spdx_id = pkg.get("SPDXID", "")
    f: Dict[str, FieldValue] = {}
    f["component_name"] = _present(pkg["name"]) if pkg.get("name") else _missing()
    f["component_version"] = _present(pkg["versionInfo"]) if pkg.get("versionInfo") else _missing()
    if pkg.get("description"):
        f["component_description"] = _present(pkg["description"])
    elif pkg.get("summary"):
        f["component_description"] = _present(pkg["summary"])
    sup = pkg.get("supplier")
    if sup and sup != NOASSERTION:
        f["component_supplier"] = _present(sup.split(":", 1)[-1].strip())
    elif sup == NOASSERTION:
        f["component_supplier"] = unknown("noassertion")
    lic = [x for x in (pkg.get("licenseDeclared"), pkg.get("licenseConcluded")) if _spdx_value(x) and x != NOASSERTION]
    if lic:
        f["component_license"] = _present(lic[:1])
    elif pkg.get("licenseDeclared") == NOASSERTION or pkg.get("licenseConcluded") == NOASSERTION:
        f["component_license"] = unknown("noassertion")
    checks = [c for c in pkg.get("checksums", []) if c.get("algorithm") and c.get("checksumValue")]
    if checks:
        f["checksums"] = _present(checks)
    if pkg.get("releaseDate"):
        f["release_date"] = _present(pkg["releaseDate"])
    if pkg.get("validUntilDate"):
        f["end_of_life_date"] = _present(pkg["validUntilDate"])
    if spdx_id in dep_map:
        f["component_dependencies"] = _present(dep_map[spdx_id])
    elif dep_state == "nested":
        f["component_dependencies"] = _present([])
    elif dep_state == "flat":
        f["component_dependencies"] = unknown("flat-dependency-graph")
    adv = [r for r in pkg.get("externalRefs", []) if r.get("referenceCategory") == "SECURITY"]
    if adv:
        f["vulnerabilities"] = _present([r.get("referenceLocator") for r in adv])
    elif vuln_analysis:
        f["vulnerabilities"] = _present([])
    _apply_properties(f, _spdx_annotation_props(pkg.get("annotations", [])))
    for rule in load_rules()["fields"]:
        f.setdefault(rule["id"], _missing())
    return NormComponent(ref=spdx_id or pkg.get("name", ""), name=pkg.get("name", ""), fields=f, is_root=is_root)


def normalize_spdx(doc: Dict[str, Any]) -> NormDoc:
    ci = doc.get("creationInfo") or {}
    doc_props = _spdx_annotation_props(doc.get("annotations", []))
    prop_map = dict(doc_props)
    relationships = doc.get("relationships", [])
    root_id = next(
        (
            r.get("relatedSpdxElement")
            for r in relationships
            if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
        ),
        None,
    )
    dep_map: Dict[str, List[str]] = {}
    for r in relationships:
        if r.get("relationshipType") == "DEPENDS_ON":
            dep_map.setdefault(r["spdxElementId"], []).append(r["relatedSpdxElement"])
    flat_declared = (PROPERTY_PREFIX + "unknown:dependency-graph") in prop_map
    if flat_declared:
        dep_state = "flat"
    elif any(src != root_id for src in dep_map):
        dep_state = "nested"
    else:
        dep_state = "none"
    vuln_analysis = prop_map.get(PROPERTY_PREFIX + "vulnerability-analysis") == "performed"

    document: Dict[str, FieldValue] = {}
    authors = [c.split(":", 1)[1].strip() for c in ci.get("creators", []) if c.startswith(("Person:", "Organization:"))]
    document["sbom_author"] = _present(authors) if authors else _missing()
    document["timestamp"] = _present(ci["created"]) if ci.get("created") else _missing()
    ids: Dict[str, str] = {}
    components = [
        _spdx_component(p, dep_map, dep_state, vuln_analysis, ids, p.get("SPDXID") == root_id)
        for p in doc.get("packages", [])
        if p.get("name")
    ]
    return NormDoc(
        format=SDOC,
        spec_version=str(doc.get("spdxVersion", "")),
        document=document,
        components=components,
        profile=prop_map.get(PROPERTY_PREFIX + "profile", "full"),
        lifecycle=prop_map.get(PROPERTY_PREFIX + "lifecycle", ""),
        level=prop_map.get(PROPERTY_PREFIX + "sbom-level", ""),
        attestation={k[len(ATTEST_PREFIX) :]: v for k, v in doc_props if k.startswith(ATTEST_PREFIX)},
    )


# ── tag-value → SPDX JSON shape ─────────────────────────────────────────────

_TV_PKG_FIELDS = {
    "PackageVersion": "versionInfo", "PackageSupplier": "supplier", "PackageDownloadLocation": "downloadLocation",
    "PackageLicenseConcluded": "licenseConcluded", "PackageLicenseDeclared": "licenseDeclared",
    "PackageCopyrightText": "copyrightText", "PrimaryPackagePurpose": "primaryPackagePurpose",
    "ReleaseDate": "releaseDate", "ValidUntilDate": "validUntilDate", "PackageDescription": "description",
}  # fmt: skip


def parse_spdx_tag_value(text: str) -> Dict[str, Any]:
    """Parse the SPDX 2.x tag-value subset both our exporter and common tools write."""
    # Join multi-line <text>...</text> values onto one line.
    joined: List[str] = []
    buf: Optional[str] = None
    for raw in text.splitlines():
        if buf is not None:
            buf += "\n" + raw
            if "</text>" in raw:
                joined.append(buf)
                buf = None
            continue
        if "<text>" in raw and "</text>" not in raw:
            buf = raw
            continue
        joined.append(raw)
    doc: Dict[str, Any] = {"creationInfo": {"creators": []}, "packages": [], "relationships": [], "annotations": []}
    pkg: Optional[Dict[str, Any]] = None
    ann: Dict[str, str] = {}

    def unwrap(v: str) -> str:
        v = v.strip()
        return v[6:-7] if v.startswith("<text>") and v.endswith("</text>") else v

    for line in joined:
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        tag, _, value = line.partition(":")
        tag, value = tag.strip(), unwrap(value)
        if tag == "SPDXVersion":
            doc["spdxVersion"] = value
        elif tag == "DocumentName":
            doc["name"] = value
        elif tag == "DocumentNamespace":
            doc["documentNamespace"] = value
        elif tag == "Creator":
            doc["creationInfo"]["creators"].append(value)
        elif tag == "Created":
            doc["creationInfo"]["created"] = value
        elif tag == "CreatorComment":
            doc["creationInfo"]["comment"] = value
        elif tag == "Relationship":
            parts = value.split(None, 2)
            if len(parts) == 3:
                doc["relationships"].append(
                    {"spdxElementId": parts[0], "relationshipType": parts[1], "relatedSpdxElement": parts[2]}
                )
        elif tag == "PackageName":
            pkg = {"name": value, "externalRefs": [], "checksums": [], "annotations": []}
            doc["packages"].append(pkg)
        elif tag == "Annotator":
            ann = {"annotator": value}
        elif tag in ("AnnotationDate", "AnnotationType"):
            ann["annotationDate" if tag == "AnnotationDate" else "annotationType"] = value
        elif tag == "SPDXREF":
            ann["ref"] = value
        elif tag == "AnnotationComment":
            ann["comment"] = value
            target = doc["annotations"] if ann.get("ref") == "SPDXRef-DOCUMENT" or pkg is None else None
            if target is None:
                for p in doc["packages"]:
                    if p.get("SPDXID") == ann.get("ref"):
                        p["annotations"].append(dict(ann))
                        break
                else:
                    doc["annotations"].append(dict(ann))
            else:
                target.append(dict(ann))
            ann = {}
        elif pkg is not None:
            if tag == "SPDXID":
                pkg["SPDXID"] = value
            elif tag in _TV_PKG_FIELDS:
                pkg[_TV_PKG_FIELDS[tag]] = value
            elif tag == "PackageChecksum":
                alg, _, val = value.partition(":")
                pkg["checksums"].append({"algorithm": alg.strip(), "checksumValue": val.strip()})
            elif tag == "ExternalRef":
                parts = value.split(None, 2)
                if len(parts) == 3:
                    pkg["externalRefs"].append(
                        {"referenceCategory": parts[0], "referenceType": parts[1], "referenceLocator": parts[2]}
                    )
    return doc


# ── entry point ─────────────────────────────────────────────────────────────


def normalize_document(content: Any) -> NormDoc:
    """Normalise parsed JSON (dict) or raw text (SPDX tag-value / JSON string)."""
    if isinstance(content, (bytes, bytearray)):
        content = content.decode("utf-8", errors="replace")
    if isinstance(content, str):
        stripped = content.lstrip()
        if stripped.startswith("{"):
            content = json.loads(content)
        elif stripped.startswith("SPDXVersion") or "SPDXVersion:" in stripped[:400]:
            return normalize_spdx(parse_spdx_tag_value(content))
        else:
            raise ValueError("Unrecognised document: not JSON and not SPDX tag-value")
    if isinstance(content, dict):
        if content.get("bomFormat") == "CycloneDX":
            return normalize_cyclonedx(content)
        if "spdxVersion" in content:
            return normalize_spdx(content)
    raise ValueError("Unrecognised document: expected CycloneDX or SPDX")
