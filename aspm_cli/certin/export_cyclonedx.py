"""CycloneDX 1.6 export (JSON and XML) carrying the CERT-In minimum fields."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import uuid
from xml.etree import ElementTree as ET

from .build import PUBLIC, Derived, cdx_alg, component_properties, license_kind, now_iso, to_iso_z
from .derive import FieldValue
from .model import Component, SbomModel
from .rules import ATTEST_PREFIX, PROPERTY_PREFIX

SPEC_VERSION = "1.6"
LIFECYCLE_PHASE = {  # CERT-In lifecycle class -> CycloneDX lifecycle phase
    "design": "design", "source": "pre-build", "build": "build",
    "analyzed": "post-build", "deployed": "operations", "runtime": "operations",
}  # fmt: skip


def _license_entries(licenses: List[str]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for lic in licenses:
        kind = license_kind(lic)
        if kind == "id":
            entries.append({"license": {"id": lic.strip()}})
        elif kind == "expression":
            entries.append({"expression": lic.strip()})
        else:
            entries.append({"license": {"name": lic.strip()}})
    # An expression entry cannot be mixed with license entries in the schema.
    if any("expression" in e for e in entries) and len(entries) > 1:
        return [
            {"expression": " OR ".join("({})".format(l.strip()) if " " in l.strip() else l.strip() for l in licenses)}
        ]
    return entries


def _component(comp: Component, fields: Dict[str, FieldValue], with_ref: bool = True) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": comp.type if comp.type else "library"}
    out["bom-ref"] = comp.ref
    if comp.supplier:
        out["supplier"] = {"name": comp.supplier}
    out["name"] = comp.name
    if comp.version:
        out["version"] = comp.version
    if comp.description:
        out["description"] = comp.description
    if comp.hashes:
        hashes = [{"alg": cdx_alg(h["alg"]), "content": h["content"]} for h in comp.hashes if cdx_alg(h.get("alg", ""))]
        if hashes:
            out["hashes"] = hashes
    if comp.licenses:
        out["licenses"] = _license_entries(comp.licenses)
    if comp.purl:
        out["purl"] = comp.purl
    # Release / end-of-life dates have no native component slot in CycloneDX 1.6.
    props = component_properties(fields)
    if comp.release_date:
        props.append(("release-date", comp.release_date))
    if comp.end_of_life_date:
        props.append(("end-of-life-date", comp.end_of_life_date))
    out["properties"] = [{"name": PROPERTY_PREFIX + k, "value": v} for k, v in props]
    return out


def _vulnerabilities(sbom: SbomModel) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for comp in ([sbom.root] if sbom.root else []) + sbom.components:
        for v in comp.vulnerabilities:
            entry = grouped.setdefault(
                v.id,
                {
                    "id": v.id,
                    "affects": [],
                    "_fixed": set(),
                    "_sev": v.severity,
                    "_cvss": v.cvss,
                    "_url": v.url,
                    "_src": v.source,
                },
            )
            entry["affects"].append({"ref": comp.ref})
            entry["_fixed"].update(v.fixed_versions)
    out: List[Dict[str, Any]] = []
    for vid, e in grouped.items():
        item: Dict[str, Any] = {"id": vid}
        src = {"name": e["_src"] or "OSV"}
        if e["_url"]:
            src["url"] = e["_url"]
        item["source"] = src
        sev = (e["_sev"] or "").lower()
        rating: Dict[str, Any] = {}
        if e["_cvss"] is not None:
            rating["score"] = e["_cvss"]
        if sev in ("critical", "high", "medium", "low", "info", "none", "unknown"):
            rating["severity"] = sev
        if rating:
            item["ratings"] = [rating]
        if e["_fixed"]:
            item["recommendation"] = "Upgrade to " + ", ".join(sorted(e["_fixed"])[:3])
        item["affects"] = e["affects"]
        out.append(item)
    return out


def build_cyclonedx(
    sbom: SbomModel, derived: Derived, profile: str = "full", attestation: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    meta = sbom.meta
    serial = meta.serial or "urn:uuid:" + str(uuid.uuid4())
    if not serial.startswith("urn:uuid:"):
        try:
            serial = "urn:uuid:" + str(uuid.UUID(serial))
        except ValueError:
            serial = "urn:uuid:" + str(uuid.uuid4())
    metadata: Dict[str, Any] = {"timestamp": to_iso_z(meta.timestamp) or now_iso()}
    if meta.lifecycle in LIFECYCLE_PHASE:
        metadata["lifecycles"] = [{"phase": LIFECYCLE_PHASE[meta.lifecycle]}]
    if meta.authors:
        metadata["authors"] = [{"name": a} for a in meta.authors]
    if meta.tools:
        metadata["tools"] = {
            "components": [
                {"type": "application", "name": t["name"], "version": t.get("version", "")} for t in meta.tools
            ]
        }
    if meta.manufacturer:
        metadata["manufacturer"] = {"name": meta.manufacturer}
    if sbom.root:
        metadata["component"] = _component(sbom.root, derived.get(sbom.root.ref, {}))
    props: List[Dict[str, str]] = []
    if meta.level:
        props.append({"name": PROPERTY_PREFIX + "sbom-level", "value": meta.level})
    if meta.lifecycle:
        props.append({"name": PROPERTY_PREFIX + "lifecycle", "value": meta.lifecycle})
    if profile == PUBLIC:
        props.append({"name": PROPERTY_PREFIX + "profile", "value": "public"})
    for k, v in (attestation or {}).items():
        props.append({"name": ATTEST_PREFIX + k, "value": v})
    if props:
        metadata["properties"] = props

    doc: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": meta.bom_version or 1,
        "metadata": metadata,
        "components": [_component(c, derived.get(c.ref, {})) for c in sbom.components],
    }
    deps: List[Dict[str, Any]] = []
    for c in ([sbom.root] if sbom.root else []) + sbom.components:
        # In a flat graph only the root has real edges; listing leaves with an
        # empty dependsOn would claim "no dependencies" instead of "unknown".
        if meta.has_nested_dependencies or c.is_root:
            deps.append({"ref": c.ref, "dependsOn": list(c.depends_on)})
    doc["dependencies"] = deps
    if not meta.has_nested_dependencies and sbom.components:
        doc["compositions"] = [{"aggregate": "unknown", "dependencies": [c.ref for c in sbom.components]}]
    if profile != PUBLIC and meta.vulnerability_analysis:
        # Present even when empty: it says the analysis ran and found nothing.
        doc["vulnerabilities"] = _vulnerabilities(sbom)
    return doc


# ── XML ─────────────────────────────────────────────────────────────────────

NS = "http://cyclonedx.org/schema/bom/" + SPEC_VERSION


def _sub(parent: ET.Element, tag: str, text: Optional[str] = None, **attrs: str) -> ET.Element:
    el = ET.SubElement(parent, tag, {k: v for k, v in attrs.items() if v is not None})
    if text is not None:
        el.text = str(text)
    return el


def _xml_component(parent: ET.Element, comp: Dict[str, Any], tag: str = "component") -> None:
    el = _sub(parent, tag, **{"type": comp.get("type", "library"), "bom-ref": comp.get("bom-ref")})
    if "supplier" in comp:
        _sub(_sub(el, "supplier"), "name", comp["supplier"]["name"])
    _sub(el, "name", comp["name"])
    if comp.get("version"):
        _sub(el, "version", comp["version"])
    if comp.get("description"):
        _sub(el, "description", comp["description"])
    if comp.get("hashes"):
        hs = _sub(el, "hashes")
        for h in comp["hashes"]:
            _sub(hs, "hash", h["content"], alg=h["alg"])
    if comp.get("licenses"):
        ls = _sub(el, "licenses")
        for entry in comp["licenses"]:
            if "expression" in entry:
                _sub(ls, "expression", entry["expression"])
            else:
                lic = _sub(ls, "license")
                if "id" in entry["license"]:
                    _sub(lic, "id", entry["license"]["id"])
                else:
                    _sub(lic, "name", entry["license"]["name"])
    if comp.get("purl"):
        _sub(el, "purl", comp["purl"])
    if comp.get("properties"):
        ps = _sub(el, "properties")
        for p in comp["properties"]:
            _sub(ps, "property", p["value"], name=p["name"])


def cyclonedx_json_to_xml(doc: Dict[str, Any]) -> str:
    ET.register_namespace("", NS)
    root = ET.Element("{%s}bom" % NS, {"serialNumber": doc["serialNumber"], "version": str(doc.get("version", 1))})

    def q(tag: str) -> str:
        return "{%s}%s" % (NS, tag)

    # Re-tag helper: build in plain tags then qualify.
    plain = ET.Element("bom")
    md = _sub(plain, "metadata")
    m = doc["metadata"]
    _sub(md, "timestamp", m["timestamp"])
    if m.get("lifecycles"):
        _sub(_sub(_sub(md, "lifecycles"), "lifecycle"), "phase", m["lifecycles"][0]["phase"])
    if m.get("tools"):
        comps = _sub(_sub(md, "tools"), "components")
        for t in m["tools"]["components"]:
            c = _sub(comps, "component", type="application")
            _sub(c, "name", t["name"])
            if t.get("version"):
                _sub(c, "version", t["version"])
    if m.get("authors"):
        authors = _sub(md, "authors")
        for a in m["authors"]:
            _sub(_sub(authors, "author"), "name", a["name"])
    if m.get("component"):
        _xml_component(md, m["component"])
    if m.get("manufacturer"):
        _sub(_sub(md, "manufacturer"), "name", m["manufacturer"]["name"])
    if m.get("properties"):
        ps = _sub(md, "properties")
        for p in m["properties"]:
            _sub(ps, "property", p["value"], name=p["name"])
    comps = _sub(plain, "components")
    for c in doc.get("components", []):
        _xml_component(comps, c)
    deps = _sub(plain, "dependencies")
    for d in doc.get("dependencies", []):
        de = _sub(deps, "dependency", ref=d["ref"])
        for child in d.get("dependsOn", []):
            _sub(de, "dependency", ref=child)
    if doc.get("compositions"):
        cs = _sub(plain, "compositions")
        for comp in doc["compositions"]:
            ce = _sub(cs, "composition")
            _sub(ce, "aggregate", comp["aggregate"])
            if comp.get("dependencies"):
                ds = _sub(ce, "dependencies")
                for ref in comp["dependencies"]:
                    _sub(ds, "dependency", ref=ref)
    if "vulnerabilities" in doc:
        vs = _sub(plain, "vulnerabilities")
        for v in doc["vulnerabilities"]:
            ve = _sub(vs, "vulnerability")
            _sub(ve, "id", v["id"])
            if v.get("source"):
                se = _sub(ve, "source")
                _sub(se, "name", v["source"]["name"])
                if v["source"].get("url"):
                    _sub(se, "url", v["source"]["url"])
            if v.get("ratings"):
                rs = _sub(ve, "ratings")
                for r in v["ratings"]:
                    re_ = _sub(rs, "rating")
                    if "score" in r:
                        _sub(re_, "score", r["score"])
                    if "severity" in r:
                        _sub(re_, "severity", r["severity"])
            if v.get("recommendation"):
                _sub(ve, "recommendation", v["recommendation"])
            af = _sub(ve, "affects")
            for a in v["affects"]:
                _sub(_sub(af, "target"), "ref", a["ref"])

    def requalify(src: ET.Element, dst: ET.Element) -> None:
        for child in src:
            new = ET.SubElement(dst, q(child.tag), child.attrib)
            new.text = child.text
            requalify(child, new)

    requalify(plain, root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
