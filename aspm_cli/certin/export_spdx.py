"""SPDX 2.3 export (JSON and tag-value) carrying the CERT-In minimum fields."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import re
import uuid

from .build import (
    PUBLIC,
    Derived,
    component_properties,
    license_kind,
    license_ref,
    now_iso,
    spdx_alg,
    spdx_supplier,
    to_iso_z,
)
from .model import SbomModel
from .rules import ATTEST_PREFIX, NOASSERTION, PROPERTY_PREFIX

PURPOSE = {
    "application": "APPLICATION", "framework": "FRAMEWORK", "library": "LIBRARY", "container": "CONTAINER",
    "operating-system": "OPERATING-SYSTEM", "device": "DEVICE", "firmware": "FIRMWARE", "file": "FILE",
}  # fmt: skip


def _spdx_id(ref: str, used: Dict[str, str]) -> str:
    if ref in used:
        return used[ref]
    base = "SPDXRef-" + (re.sub(r"[^A-Za-z0-9.\-]+", "-", ref).strip("-") or "pkg")[:80]
    candidate, n = base, 1
    taken = set(used.values())
    while candidate in taken or candidate == "SPDXRef-DOCUMENT":
        n += 1
        candidate = "{}-{}".format(base, n)
    used[ref] = candidate
    return candidate


def _license_expr(licenses: List[str], extracted: Dict[str, str]) -> str:
    if not licenses:
        return NOASSERTION
    parts: List[str] = []
    for lic in licenses:
        text = lic.strip()
        if license_kind(text) in ("id", "expression"):
            parts.append(text)
        else:
            ref = license_ref(text)
            extracted[ref] = text
            parts.append(ref)
    if len(parts) == 1:
        return parts[0]
    return " OR ".join("({})".format(p) if " " in p else p for p in parts)


def _annotation(annotator: str, date: str, text: str) -> Dict[str, str]:
    return {"annotationType": "OTHER", "annotator": annotator, "annotationDate": date, "comment": text}


def build_spdx(
    sbom: SbomModel, derived: Derived, profile: str = "full", attestation: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    meta = sbom.meta
    created = to_iso_z(meta.timestamp) or now_iso()
    tool = meta.tools[0] if meta.tools else {"name": "AccuKnox", "version": ""}
    tool_label = "Tool: {}{}".format(tool["name"], "-" + tool["version"] if tool.get("version") else "")
    creators = [tool_label] + ["Person: " + a for a in meta.authors]
    if meta.manufacturer:
        creators.append("Organization: " + meta.manufacturer)
    if meta.supplier and meta.supplier != meta.manufacturer:
        creators.append("Organization: " + meta.supplier)
    namespace_id = meta.serial.replace("urn:uuid:", "") if meta.serial else str(uuid.uuid4())

    used: Dict[str, str] = {}
    extracted: Dict[str, str] = {}
    packages: List[Dict[str, Any]] = []
    relationships: List[Dict[str, str]] = []
    all_components = ([sbom.root] if sbom.root else []) + sbom.components
    for c in all_components:
        _spdx_id(c.ref, used)

    for c in all_components:
        fields = derived.get(c.ref, {})
        pkg: Dict[str, Any] = {
            "SPDXID": used[c.ref],
            "name": c.name,
            "downloadLocation": NOASSERTION,
            "filesAnalyzed": False,
            "supplier": spdx_supplier(c.supplier),
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": _license_expr(c.licenses, extracted),
            "copyrightText": NOASSERTION,
            "primaryPackagePurpose": PURPOSE.get((c.type or "library").lower(), "LIBRARY"),
        }
        if c.version:
            pkg["versionInfo"] = c.version
        if c.description:
            pkg["description"] = c.description
        checks = [
            {"algorithm": spdx_alg(h["alg"]), "checksumValue": h["content"]}
            for h in c.hashes
            if spdx_alg(h.get("alg", ""))
        ]
        if checks:
            pkg["checksums"] = checks
        ext_refs: List[Dict[str, str]] = []
        if c.purl:
            ext_refs.append(
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c.purl}
            )
        if profile != PUBLIC:
            for v in c.vulnerabilities:
                ext_refs.append(
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "advisory",
                        "referenceLocator": v.url or "https://osv.dev/vulnerability/" + v.id,
                    }
                )
        if ext_refs:
            pkg["externalRefs"] = ext_refs
        rd, eol = to_iso_z(c.release_date), to_iso_z(c.end_of_life_date)
        if rd:
            pkg["releaseDate"] = rd
        if eol:
            pkg["validUntilDate"] = eol
        props = component_properties(fields)
        if profile != PUBLIC:
            for v in c.vulnerabilities:
                props.append(
                    (
                        "vulnerability",
                        "{};severity={};fixed={}".format(
                            v.id, v.severity or "unknown", ",".join(v.fixed_versions) or "none"
                        ),
                    )
                )
        pkg["annotations"] = [
            _annotation(tool_label, created, "{}{}={}".format(PROPERTY_PREFIX, k, v)) for k, v in props
        ]
        packages.append(pkg)

    if sbom.root:
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": used[sbom.root.ref],
            }
        )
    for c in all_components:
        for dep in c.depends_on:
            if dep in used:
                relationships.append(
                    {"spdxElementId": used[c.ref], "relationshipType": "DEPENDS_ON", "relatedSpdxElement": used[dep]}
                )

    doc_annotations = (
        [_annotation(tool_label, created, "{}sbom-level={}".format(PROPERTY_PREFIX, meta.level))] if meta.level else []
    )
    if meta.lifecycle:
        doc_annotations.append(
            _annotation(tool_label, created, "{}lifecycle={}".format(PROPERTY_PREFIX, meta.lifecycle))
        )
    if meta.comments and profile != PUBLIC:
        doc_annotations.append(_annotation(tool_label, created, PROPERTY_PREFIX + "comments=" + meta.comments))
    if meta.vulnerability_analysis and profile != PUBLIC:
        doc_annotations.append(_annotation(tool_label, created, PROPERTY_PREFIX + "vulnerability-analysis=performed"))
    if not meta.has_nested_dependencies:
        doc_annotations.append(
            _annotation(tool_label, created, PROPERTY_PREFIX + "unknown:dependency-graph=flat-dependency-graph")
        )
    if profile == PUBLIC:
        doc_annotations.append(_annotation(tool_label, created, PROPERTY_PREFIX + "profile=public"))
    for k, v in (attestation or {}).items():
        doc_annotations.append(_annotation(tool_label, created, "{}{}={}".format(ATTEST_PREFIX, k, v)))

    creation: Dict[str, Any] = {"created": created, "creators": creators}
    if attestation:
        creation["comment"] = "CERT-In SBOM data-field check: {} ({})".format(
            attestation.get("status", ""), attestation.get("profile", "")
        )
    doc: Dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": meta.name or (sbom.root.name if sbom.root else "sbom"),
        "documentNamespace": "https://accuknox.com/spdx/{}/{}".format(
            re.sub(r"[^A-Za-z0-9.\-]+", "-", meta.name or "sbom"), namespace_id
        ),
        "creationInfo": creation,
        "packages": packages,
        "relationships": relationships,
    }
    if extracted:
        doc["hasExtractedLicensingInfos"] = [
            {"licenseId": k, "extractedText": v, "name": v} for k, v in extracted.items()
        ]
    if doc_annotations:
        doc["annotations"] = [dict(a, **{"annotationType": "OTHER"}) for a in doc_annotations]
    return doc


# ── tag-value ───────────────────────────────────────────────────────────────


def _text(value: str) -> str:
    return "<text>{}</text>".format(value) if "\n" in value or len(value) > 120 else value


def spdx_json_to_tag_value(doc: Dict[str, Any]) -> str:
    lines: List[str] = [
        "SPDXVersion: " + doc["spdxVersion"],
        "DataLicense: " + doc["dataLicense"],
        "SPDXID: " + doc["SPDXID"],
        "DocumentName: " + doc["name"],
        "DocumentNamespace: " + doc["documentNamespace"],
    ]
    for creator in doc["creationInfo"]["creators"]:
        lines.append("Creator: " + creator)
    lines.append("Created: " + doc["creationInfo"]["created"])
    if doc["creationInfo"].get("comment"):
        lines.append("CreatorComment: " + _text(doc["creationInfo"]["comment"]))
    for info in doc.get("hasExtractedLicensingInfos", []):
        lines += ["", "LicenseID: " + info["licenseId"], "ExtractedText: <text>{}</text>".format(info["extractedText"])]
    for rel in doc.get("relationships", []):
        lines.append(
            "Relationship: {} {} {}".format(rel["spdxElementId"], rel["relationshipType"], rel["relatedSpdxElement"])
        )
    for ann in doc.get("annotations", []):
        lines += _annotation_lines(ann, "SPDXRef-DOCUMENT")
    for pkg in doc["packages"]:
        lines += ["", "PackageName: " + pkg["name"], "SPDXID: " + pkg["SPDXID"]]
        if pkg.get("versionInfo"):
            lines.append("PackageVersion: " + pkg["versionInfo"])
        lines.append("PackageSupplier: " + pkg["supplier"])
        lines.append("PackageDownloadLocation: " + pkg["downloadLocation"])
        lines.append("FilesAnalyzed: " + str(pkg["filesAnalyzed"]).lower())
        for ch in pkg.get("checksums", []):
            lines.append("PackageChecksum: {}: {}".format(ch["algorithm"], ch["checksumValue"]))
        lines.append("PackageLicenseConcluded: " + pkg["licenseConcluded"])
        lines.append("PackageLicenseDeclared: " + pkg["licenseDeclared"])
        lines.append("PackageCopyrightText: " + pkg["copyrightText"])
        if pkg.get("description"):
            lines.append("PackageDescription: <text>{}</text>".format(pkg["description"]))
        lines.append("PrimaryPackagePurpose: " + pkg["primaryPackagePurpose"])
        if pkg.get("releaseDate"):
            lines.append("ReleaseDate: " + pkg["releaseDate"])
        if pkg.get("validUntilDate"):
            lines.append("ValidUntilDate: " + pkg["validUntilDate"])
        for ref in pkg.get("externalRefs", []):
            lines.append(
                "ExternalRef: {} {} {}".format(ref["referenceCategory"], ref["referenceType"], ref["referenceLocator"])
            )
        for ann in pkg.get("annotations", []):
            lines += _annotation_lines(ann, pkg["SPDXID"])
    return "\n".join(lines) + "\n"


def _annotation_lines(ann: Dict[str, str], spdx_ref: str) -> List[str]:
    return [
        "Annotator: " + ann["annotator"],
        "AnnotationDate: " + ann["annotationDate"],
        "AnnotationType: " + ann["annotationType"],
        "SPDXREF: " + spdx_ref,
        "AnnotationComment: <text>{}</text>".format(ann["comment"]),
    ]
