"""Read VEX statements (OpenVEX, CycloneDX VEX, CSAF) and write them into a CycloneDX SBOM.

Trivy only *consumes* a VEX file (``--vex``): it drops the vulnerabilities a statement marks not
affected or fixed and leaves no trace of why. This module records the statements themselves in the
SBOM as ``vulnerabilities[].analysis`` so the platform can show them, and so a reader of the file can
see that a CVE was assessed rather than absent.

A statement applies to a component when the product's package URL (ignoring qualifiers) equals the
component's, or names no version and the same package. Statements that match no component are
dropped: they describe something that is not in this SBOM.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

# OpenVEX / CSAF status -> CycloneDX analysis.state
_STATE = {
    "not_affected": "not_affected",
    "known_not_affected": "not_affected",
    "fixed": "resolved",
    "affected": "exploitable",
    "known_affected": "exploitable",
    "under_investigation": "in_triage",
}
# OpenVEX / CSAF justification -> CycloneDX analysis.justification
_JUSTIFICATION = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "protected_by_mitigating_control",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}
CDX_STATES = {"resolved", "resolved_with_pedigree", "exploitable", "in_triage", "false_positive", "not_affected"}


class VexError(ValueError):
    """The file is not a VEX document this tool understands."""


def purl_key(purl: str) -> Tuple[str, Optional[str]]:
    """``(package identity, version)`` of a package URL, without qualifiers or subpath."""
    text = str(purl).split("#", 1)[0].split("?", 1)[0]
    ident, sep, version = text.rpartition("@")
    if not sep or "/" in version:  # no version, or the "@" was a scope marker (pkg:npm/@scope/name)
        ident, version = text, ""
    return ident.lower().replace("%40", "@"), (version or None)


def _statement(vuln: str, status: str, products: Iterable[str], justification=None, detail=None) -> Optional[Dict]:
    state = _STATE.get(str(status).lower()) or (str(status).lower() if str(status).lower() in CDX_STATES else None)
    if not vuln or not state:
        return None
    analysis: Dict[str, Any] = {"state": state}
    if justification and _JUSTIFICATION.get(str(justification)):
        analysis["justification"] = _JUSTIFICATION[str(justification)]
    elif justification and str(justification) in _JUSTIFICATION.values():
        analysis["justification"] = str(justification)
    if detail:
        analysis["detail"] = str(detail)[:2000]
    return {"id": str(vuln), "analysis": analysis, "products": [p for p in products if p]}


def _openvex(doc: Dict[str, Any]) -> List[Dict]:
    out = []
    for item in doc.get("statements", []) or []:
        vuln = item.get("vulnerability")
        name = vuln.get("name") if isinstance(vuln, dict) else vuln
        products = []
        for product in item.get("products", []) or []:
            if isinstance(product, str):
                products.append(product)
                continue
            products.append((product.get("identifiers") or {}).get("purl") or product.get("@id"))
            for sub in product.get("subcomponents", []) or []:
                products.append((sub.get("identifiers") or {}).get("purl") or sub.get("@id"))
        detail = item.get("impact_statement") or item.get("action_statement")
        stmt = _statement(name, item.get("status"), products, item.get("justification"), detail)
        if stmt:
            out.append(stmt)
    return out


def _cyclonedx(doc: Dict[str, Any]) -> List[Dict]:
    out = []
    for item in doc.get("vulnerabilities", []) or []:
        analysis = item.get("analysis") or {}
        stmt = _statement(
            item.get("id"),
            analysis.get("state"),
            [a.get("ref") for a in item.get("affects", []) or [] if isinstance(a, dict)],
            analysis.get("justification"),
            analysis.get("detail"),
        )
        if stmt:
            out.append(stmt)
    return out


def _csaf_products(tree: Any, found: Dict[str, str]) -> None:
    if isinstance(tree, dict):
        full = tree.get("product")
        if isinstance(full, dict) and full.get("product_id"):
            purl = (full.get("product_identification_helper") or {}).get("purl")
            if purl:
                found[full["product_id"]] = purl
        for value in tree.values():
            _csaf_products(value, found)
    elif isinstance(tree, list):
        for value in tree:
            _csaf_products(value, found)


def _csaf(doc: Dict[str, Any]) -> List[Dict]:
    purls: Dict[str, str] = {}
    _csaf_products(doc.get("product_tree") or {}, purls)
    out = []
    for item in doc.get("vulnerabilities", []) or []:
        flags: Dict[str, str] = {}
        for flag in item.get("flags", []) or []:
            for pid in flag.get("product_ids", []) or []:
                flags[pid] = flag.get("label")
        for status, ids in (item.get("product_status") or {}).items():
            for pid in ids or []:
                stmt = _statement(item.get("cve"), status, [purls.get(pid, pid)], flags.get(pid))
                if stmt:
                    out.append(stmt)
    return out


def parse_vex(doc: Dict[str, Any]) -> List[Dict]:
    """The statements of an OpenVEX, CycloneDX VEX or CSAF document."""
    if not isinstance(doc, dict):
        raise VexError("not a JSON object")
    if "statements" in doc and "@context" in doc:
        return _openvex(doc)
    if doc.get("bomFormat") == "CycloneDX":
        return _cyclonedx(doc)
    if isinstance(doc.get("document"), dict):
        return _csaf(doc)
    raise VexError("not an OpenVEX, CycloneDX VEX or CSAF document")


def load_vex(path: str) -> List[Dict]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return parse_vex(json.load(handle))
    except (OSError, json.JSONDecodeError) as exc:
        raise VexError("cannot read {}: {}".format(path, exc))


def _matches(product: str, comp: Dict[str, Any]) -> bool:
    if product in (comp.get("bom-ref"),):
        return True
    if not comp.get("purl") or not str(product).startswith("pkg:"):
        return False
    p_ident, p_version = purl_key(product)
    c_ident, c_version = purl_key(comp["purl"])
    return p_ident == c_ident and (p_version is None or p_version == c_version)


def apply_vex(doc: Dict[str, Any], statements: List[Dict]) -> Dict[str, int]:
    """Write ``statements`` into ``doc['vulnerabilities']`` as ``analysis``; returns what was done."""
    comps = [c for c in doc.get("components", []) if isinstance(c, dict)]
    if isinstance(doc.get("metadata", {}).get("component"), dict):
        comps.append(doc["metadata"]["component"])
    vulns: List[Dict[str, Any]] = doc.setdefault("vulnerabilities", [])
    by_id = {v.get("id"): v for v in vulns if isinstance(v, dict)}
    applied = skipped = 0
    for stmt in statements:
        refs = []
        for comp in comps:
            ref = comp.get("bom-ref") or comp.get("purl")
            if ref and any(_matches(p, comp) for p in stmt["products"]):
                refs.append(ref)
        if not refs:
            skipped += 1
            continue
        entry = by_id.get(stmt["id"])
        if entry is None:
            entry = {"id": stmt["id"], "source": {"name": "VEX"}, "affects": []}
            vulns.append(entry)
            by_id[stmt["id"]] = entry
        entry["analysis"] = stmt["analysis"]
        listed = {a.get("ref") for a in entry.get("affects", []) if isinstance(a, dict)}
        entry.setdefault("affects", []).extend({"ref": r} for r in refs if r not in listed)
        applied += 1
    return {"applied": applied, "skipped": skipped}
