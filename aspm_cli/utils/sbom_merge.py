"""Merge Trivy, Syft and source-inferred components into one CycloneDX document.

Trivy is the primary document (its vulnerabilities, dependency graph and bom-refs are kept).
Syft fills gaps on components both found and contributes the components only it found.
Inferred components are appended last. Findings for the components Trivy never saw are produced
by the caller (``trivy sbom`` over :func:`build_delta_bom`) and folded in with
:func:`merge_vulnerabilities`.
"""
from __future__ import annotations

import copy
import hashlib
import re
from urllib.parse import unquote
from typing import Any, Dict, Iterable, List, Optional, Tuple

from aspm_cli.inference.base import LOOKUP_BLOCKED_PURL_TYPES, normalize_dep_name
from aspm_cli.utils.sbom_license_merge import normalized_license_entries

SKIP_COMPONENT_TYPES = frozenset({"file"})
_QUALIFIER_RE = re.compile(r"[?#].*$")


def purl_key(purl: Optional[str]) -> Optional[str]:
    """Qualifier-free, lower-cased purl used to decide two components are the same package."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    return unquote(_QUALIFIER_RE.sub("", purl)).lower()


def component_keys(component: Dict[str, Any]) -> List[Tuple[str, str]]:
    keys: List[Tuple[str, str]] = []
    purl = purl_key(component.get("purl"))
    if purl:
        keys.append(("purl", purl))
    name, version = component.get("name"), component.get("version")
    if isinstance(name, str) and name.strip() and isinstance(version, str) and version.strip():
        keys.append(("nv", f"{normalize_dep_name(name)}@{version.strip().lower()}"))
    return keys


def _prop_names(component: Dict[str, Any]) -> set:
    return {p.get("name") for p in component.get("properties") or [] if isinstance(p, dict)}


def _fill_gaps(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    """Copy fields ``target`` lacks from ``source`` without overwriting anything Trivy reported."""
    if not target.get("licenses"):
        licenses = normalized_license_entries(source)
        if licenses:
            target["licenses"] = licenses
    for field in ("hashes", "cpe", "supplier", "publisher", "author", "description", "evidence"):
        if source.get(field) and not target.get(field):
            target[field] = copy.deepcopy(source[field])
    refs = source.get("externalReferences")
    if refs:
        have = {(r.get("type"), r.get("url")) for r in target.get("externalReferences") or [] if isinstance(r, dict)}
        for ref in refs:
            if isinstance(ref, dict) and (ref.get("type"), ref.get("url")) not in have:
                target.setdefault("externalReferences", []).append(copy.deepcopy(ref))
    existing = _prop_names(target)
    for prop in source.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") not in existing:
            target.setdefault("properties", []).append(copy.deepcopy(prop))


def _unique_ref(ref: str, taken: set) -> str:
    if ref not in taken:
        return ref
    n = 2
    while f"{ref}~{n}" in taken:
        n += 1
    return f"{ref}~{n}"


def merge_components(
    base: Dict[str, Any],
    extra: Dict[str, Any],
    origin: str,
) -> Tuple[Dict[str, str], Dict[str, int]]:
    """Merge ``extra``'s components into ``base`` in place.

    Returns (ref_map extra-ref -> merged-ref, stats). ``origin`` is stamped on appended components
    as ``accuknox:found-by`` so a reader can tell which engine contributed them.
    """
    components = base.setdefault("components", [])
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    taken = set()
    for comp in components:
        if isinstance(comp, dict):
            taken.add(comp.get("bom-ref"))
            for key in component_keys(comp):
                index.setdefault(key, comp)
    root = (base.get("metadata") or {}).get("component")
    if isinstance(root, dict):
        taken.add(root.get("bom-ref"))

    ref_map: Dict[str, str] = {}
    stats = {"matched": 0, "added": 0, "skipped": 0}
    for comp in extra.get("components") or []:
        if not isinstance(comp, dict) or not comp.get("name") or comp.get("type") in SKIP_COMPONENT_TYPES:
            stats["skipped"] += 1
            continue
        match = next((index[k] for k in component_keys(comp) if k in index), None)
        if match is not None:
            _fill_gaps(match, comp)
            if comp.get("bom-ref") and match.get("bom-ref"):
                ref_map[comp["bom-ref"]] = match["bom-ref"]
            stats["matched"] += 1
            continue
        new = copy.deepcopy(comp)
        old_ref = new.get("bom-ref")
        new_ref = _unique_ref(old_ref or new.get("purl") or f"{origin}:{new['name']}", taken)
        new["bom-ref"] = new_ref
        taken.add(new_ref)
        if old_ref:
            ref_map[old_ref] = new_ref
        if not any(p.get("name") == "accuknox:found-by" for p in new.get("properties") or [] if isinstance(p, dict)):
            new.setdefault("properties", []).append({"name": "accuknox:found-by", "value": origin})
        components.append(new)
        for key in component_keys(new):
            index.setdefault(key, new)
        stats["added"] += 1

    extra_root = (extra.get("metadata") or {}).get("component")
    if isinstance(root, dict) and isinstance(extra_root, dict) and extra_root.get("bom-ref") and root.get("bom-ref"):
        ref_map[extra_root["bom-ref"]] = root["bom-ref"]
    _merge_dependencies(base, extra, ref_map)
    return ref_map, stats


def _merge_dependencies(base: Dict[str, Any], extra: Dict[str, Any], ref_map: Dict[str, str]) -> None:
    edges: Dict[str, List[str]] = {}
    for dep in base.get("dependencies") or []:
        if isinstance(dep, dict) and dep.get("ref"):
            edges[dep["ref"]] = list(dep.get("dependsOn") or [])
    known = {c.get("bom-ref") for c in base.get("components") or [] if isinstance(c, dict)}
    root = ((base.get("metadata") or {}).get("component") or {}).get("bom-ref")
    known.add(root)
    for dep in extra.get("dependencies") or []:
        if not isinstance(dep, dict) or not dep.get("ref"):
            continue
        ref = ref_map.get(dep["ref"], dep["ref"])
        if ref not in known:
            continue
        targets = edges.setdefault(ref, [])
        for child in dep.get("dependsOn") or []:
            child = ref_map.get(child, child)
            if child in known and child not in targets:
                targets.append(child)
    if edges:
        base["dependencies"] = [{"ref": ref, "dependsOn": sorted(set(deps))} for ref, deps in edges.items()]


def link_added_components(doc: Dict[str, Any], original_refs: set) -> int:
    """Give every component added by the merge a dependency entry, as Trivy does for its own.

    A component nothing depends on becomes a direct dependency of the root (it was found in the
    project, so the project uses it); an empty ``dependsOn`` records "no known dependencies".
    Returns the number of entries added.
    """
    entries: Dict[str, Dict[str, Any]] = {
        d["ref"]: d for d in doc.get("dependencies") or [] if isinstance(d, dict) and d.get("ref")
    }
    depended = {child for d in entries.values() for child in d.get("dependsOn") or []}
    root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    added = 0
    for comp in doc.get("components") or []:
        ref = comp.get("bom-ref") if isinstance(comp, dict) else None
        if not ref or ref in original_refs:
            continue
        if ref not in entries:
            entries[ref] = {"ref": ref, "dependsOn": []}
            added += 1
        if root and ref not in depended and ref != root:
            entries.setdefault(root, {"ref": root, "dependsOn": []}).setdefault("dependsOn", []).append(ref)
            depended.add(ref)
    if entries:
        doc["dependencies"] = list(entries.values())
    return added


def append_components(base: Dict[str, Any], components: Iterable[Dict[str, Any]], origin: str) -> Dict[str, int]:
    """Append already-built components (e.g. inferred) that match nothing in ``base``."""
    return merge_components(base, {"components": list(components)}, origin)[1]


def merge_vulnerabilities(base: Dict[str, Any], extra: Dict[str, Any], ref_map: Optional[Dict[str, str]] = None) -> int:
    """Fold ``extra``'s vulnerabilities into ``base``; the same id on the same component is kept once.

    Returns the number of (vulnerability, component) pairs added.
    """
    ref_map = ref_map or {}
    vulns: List[Dict[str, Any]] = base.setdefault("vulnerabilities", [])
    by_id: Dict[str, Dict[str, Any]] = {v.get("id"): v for v in vulns if isinstance(v, dict) and v.get("id")}
    added = 0
    for vuln in extra.get("vulnerabilities") or []:
        if not isinstance(vuln, dict) or not vuln.get("id"):
            continue
        affects = []
        for affect in vuln.get("affects") or []:
            if isinstance(affect, dict) and affect.get("ref"):
                mapped = copy.deepcopy(affect)
                mapped["ref"] = ref_map.get(affect["ref"], affect["ref"])
                affects.append(mapped)
        current = by_id.get(vuln["id"])
        if current is None:
            new = copy.deepcopy(vuln)
            new["affects"] = affects
            vulns.append(new)
            by_id[new["id"]] = new
            added += len(affects)
            continue
        have = {a.get("ref") for a in current.get("affects") or [] if isinstance(a, dict)}
        for affect in affects:
            if affect["ref"] not in have:
                current.setdefault("affects", []).append(affect)
                have.add(affect["ref"])
                added += 1
    return added


def is_lookup_candidate(component: Dict[str, Any]) -> bool:
    """Eligible for a ``trivy sbom`` advisory pass: resolved version on a registry-style purl."""
    purl = component.get("purl")
    version = component.get("version")
    if not version or str(version).strip().upper() in ("UNKNOWN", "NOASSERTION", "NONE"):
        return False
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return False
    return purl[4:].split("/", 1)[0].lower() not in LOOKUP_BLOCKED_PURL_TYPES


def build_delta_bom(merged: Dict[str, Any], original_refs: set) -> Optional[Dict[str, Any]]:
    """A CycloneDX document with only the lookup-eligible components Trivy did not report itself.

    ``None`` when there is nothing to look up.
    """
    delta = [
        {k: v for k, v in c.items() if k in ("type", "bom-ref", "name", "version", "purl", "cpe", "group")}
        for c in merged.get("components") or []
        if isinstance(c, dict) and c.get("bom-ref") not in original_refs and is_lookup_candidate(c)
    ]
    if not delta:
        return None
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": delta}


def count_components(doc: Dict[str, Any]) -> int:
    return len([c for c in doc.get("components") or [] if isinstance(c, dict)])


# ── SPDX ─────────────────────────────────────────────────────────────────────────────────────────

NOASSERTION = "NOASSERTION"


def _spdx_package_view(package: Dict[str, Any]) -> Dict[str, Any]:
    purl = next(
        (r.get("referenceLocator") for r in package.get("externalRefs") or []
         if isinstance(r, dict) and r.get("referenceType") == "purl"),
        None,
    )
    view: Dict[str, Any] = {"bom-ref": package.get("SPDXID"), "name": package.get("name"), "type": "library"}
    if package.get("versionInfo"):
        view["version"] = package["versionInfo"]
    if purl:
        view["purl"] = purl
    return view


def _spdx_license(component: Dict[str, Any]) -> str:
    entries = normalized_license_entries(component)
    ids = [e.get("expression") or (e.get("license") or {}).get("id") for e in entries]
    ids = [i for i in ids if i]
    return " AND ".join(ids) if ids else NOASSERTION


def _spdx_comment(component: Dict[str, Any]) -> str:
    props = {p.get("name"): p.get("value") for p in component.get("properties") or [] if isinstance(p, dict)}
    parts = []
    for key, label in (("accuknox:found-by", "found-by"), ("accuknox:inferred", "inferred"),
                       ("accuknox:confidence", "confidence"), ("accuknox:source", "source"),
                       ("accuknox:evidence", "evidence"), ("accuknox:version-constraint", "version-constraint")):
        if props.get(key):
            parts.append(f"{label}={props[key]}")
    return "; ".join(parts)


def spdx_to_cyclonedx_index(spdx: Dict[str, Any]) -> Dict[str, Any]:
    """A components-only CycloneDX view of an SPDX document, for matching with :func:`merge_components`."""
    return {"components": [
        _spdx_package_view(p) for p in spdx.get("packages") or [] if isinstance(p, dict) and p.get("name")
    ]}


def merge_into_spdx(
    spdx: Dict[str, Any],
    syft: Optional[Dict[str, Any]],
    inferred: Iterable[Dict[str, Any]] = (),
) -> Dict[str, int]:
    """Add the packages Syft and source inference found, and Trivy's SPDX lacks, to ``spdx`` in place.

    Matching and de-duplication reuse the CycloneDX logic over a components-only view of the
    document. SPDX carries no vulnerabilities, so there is no advisory pass here; added packages
    are recorded with what found them in ``comment``. Returns merge stats.
    """
    index = spdx_to_cyclonedx_index(spdx)
    existing_refs = {c["bom-ref"] for c in index["components"]}
    stats = {"matched": 0, "added": 0}
    if syft:
        _, st = merge_components(index, syft, "inventory")
        stats["matched"] += st["matched"]
    inferred = list(inferred)
    if inferred:
        append_components(index, inferred, "source-inference")
    packages = spdx.setdefault("packages", [])
    relationships = spdx.setdefault("relationships", [])
    root = next((r.get("relatedSpdxElement") for r in relationships
                 if isinstance(r, dict) and r.get("relationshipType") == "DESCRIBES"), None)
    taken = {p.get("SPDXID") for p in packages if isinstance(p, dict)}
    for comp in index["components"]:
        if comp["bom-ref"] in existing_refs:
            continue
        digest = hashlib.sha1((comp.get("purl") or comp["name"]).encode("utf-8")).hexdigest()[:12]
        spdx_id = f"SPDXRef-Package-{re.sub(r'[^A-Za-z0-9.-]', '-', comp['name'])}-{digest}"
        if spdx_id in taken:
            continue
        taken.add(spdx_id)
        pkg: Dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": comp["name"],
            "downloadLocation": NOASSERTION,
            "filesAnalyzed": False,
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": _spdx_license(comp),
            "copyrightText": NOASSERTION,
        }
        if comp.get("version"):
            pkg["versionInfo"] = comp["version"]
        refs = []
        if comp.get("purl"):
            refs.append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": comp["purl"]})
        if comp.get("cpe"):
            refs.append({"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": comp["cpe"]})
        if refs:
            pkg["externalRefs"] = refs
        comment = _spdx_comment(comp)
        if comment:
            pkg["comment"] = comment
        packages.append(pkg)
        if root:
            relationships.append({"spdxElementId": root, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": spdx_id})
        stats["added"] += 1
    return stats
