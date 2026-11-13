"""Read a scanner-produced CycloneDX or SPDX JSON document into an :class:`SbomModel`.

The CLI uses this to derive the CERT-In fields for an SBOM it has just
generated, and to add them to the file without rebuilding it (a rebuild would
drop tool-specific properties the platform relies on).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import re
from collections import deque

from .model import Component, DocumentMeta, SbomModel, Vulnerability
from .rules import PROPERTY_PREFIX

_PHASE_TO_LIFECYCLE = {
    "design": "design", "pre-build": "source", "build": "build", "post-build": "analyzed", "operations": "deployed",
}  # fmt: skip
_VERSION = re.compile(r"(\d+(?:\.\d+)+[\w.\-+]*)")


def _depth_and_dependents(root_ref: Optional[str], edges: Dict[str, List[str]]) -> Dict[str, Any]:
    depth: Dict[str, int] = {}
    if root_ref:
        depth[root_ref] = 0
        queue = deque([root_ref])
        while queue:
            node = queue.popleft()
            for child in edges.get(node, []):
                if child not in depth:
                    depth[child] = depth[node] + 1
                    queue.append(child)
    indegree: Dict[str, int] = {}
    for dsts in edges.values():
        for dst in dsts:
            indegree[dst] = indegree.get(dst, 0) + 1
    return {"depth": depth, "indegree": indegree}


def _props(items: Any) -> Dict[str, str]:
    return {p["name"]: p.get("value", "") for p in items or [] if isinstance(p, dict) and p.get("name")}


def vulnerabilities_from_cyclonedx(doc: Dict[str, Any], limit: int = 20000) -> List[Dict[str, Any]]:
    """The ``vulnerabilities`` a scanner wrote into a CycloneDX document, as plain dicts.

    ``[{id, severity, cvss, fixed, url, source, affects: [bom-ref, ...]}]``. The platform keeps these
    so its export does not claim "none reported" for what the uploaded file itself listed.
    """
    out: List[Dict[str, Any]] = []
    for v in doc.get("vulnerabilities", []) or []:
        if not isinstance(v, dict) or not v.get("id"):
            continue
        ratings = v.get("ratings") or []
        rating = next((r for r in ratings if r.get("severity")), ratings[0] if ratings else {})
        rec = v.get("recommendation") or ""
        match = _VERSION.search(rec)
        analysis = v.get("analysis") if isinstance(v.get("analysis"), dict) else {}
        vex = {k: str(analysis[k]) for k in ("state", "justification", "detail") if analysis.get(k)}
        if analysis.get("response"):
            vex["response"] = (
                [str(r) for r in analysis["response"]]
                if isinstance(analysis["response"], list)
                else [str(analysis["response"])]
            )
        out.append(
            {
                **({"analysis": vex} if vex else {}),
                "id": v["id"],
                "severity": str(rating.get("severity") or "unknown").lower(),
                "cvss": rating.get("score"),
                "fixed": [match.group(1)] if match else (["see-advisory"] if rec else []),
                "description": str(v.get("description") or v.get("detail") or "")[:2000],
                "url": (v.get("source") or {}).get("url", ""),
                "source": (v.get("source") or {}).get("name", ""),
                "affects": [a["ref"] for a in v.get("affects", []) or [] if isinstance(a, dict) and a.get("ref")],
            }
        )
        if len(out) >= limit:
            break
    return out


# ── CycloneDX ───────────────────────────────────────────────────────────────


def _cdx_component(raw: Dict[str, Any], is_root: bool, analysed: bool) -> Component:
    lics: List[str] = []
    for entry in raw.get("licenses", []) or []:
        if "expression" in entry:
            lics.append(entry["expression"])
        elif isinstance(entry.get("license"), dict):
            lics.append(entry["license"].get("id") or entry["license"].get("name") or "")
    ref = raw.get("bom-ref") or raw.get("purl") or "{}@{}".format(raw.get("name", ""), raw.get("version", ""))
    extra: Dict[str, Any] = {}
    for prop in raw.get("properties", []) or []:
        if prop.get("name") == "certin:supplier-source":
            extra["supplier_source"] = prop.get("value")  # e.g. purl-namespace: a proxy, not a declared supplier
    return Component(
        ref=ref,
        name=raw.get("name", ""),
        version=raw.get("version"),
        type=(raw.get("type") or "library").lower(),
        purl=raw.get("purl"),
        description=raw.get("description"),
        supplier=(raw.get("supplier") or {}).get("name") or raw.get("publisher"),
        licenses=[x for x in lics if x],
        hashes=[
            {"alg": h["alg"], "content": h["content"]}
            for h in raw.get("hashes", []) or []
            if h.get("alg") and h.get("content")
        ],
        is_root=is_root,
        vulnerabilities_checked=analysed and bool(raw.get("purl")),
        extra=extra,
    )


def model_from_cyclonedx(doc: Dict[str, Any]) -> SbomModel:
    md = doc.get("metadata") or {}
    analysed = "vulnerabilities" in doc
    root_raw = md.get("component") if isinstance(md.get("component"), dict) else None
    root = _cdx_component(root_raw, True, analysed) if root_raw and root_raw.get("name") else None
    components = [
        _cdx_component(c, False, analysed) for c in doc.get("components", []) if isinstance(c, dict) and c.get("name")
    ]
    by_ref = {c.ref: c for c in ([root] if root else []) + components}

    edges: Dict[str, List[str]] = {}
    for dep in doc.get("dependencies", []) or []:
        if dep.get("ref") in by_ref:
            edges[dep["ref"]] = [d for d in dep.get("dependsOn", []) if d in by_ref]
            by_ref[dep["ref"]].depends_on = edges[dep["ref"]]
    stats = _depth_and_dependents(root.ref if root else None, edges)
    for c in by_ref.values():
        c.depth = stats["depth"].get(c.ref, 2)
        c.dependents = stats["indegree"].get(c.ref, 0)

    for v in vulnerabilities_from_cyclonedx(doc):
        for ref in v["affects"]:
            target = by_ref.get(ref)
            if target is not None:
                target.vulnerabilities.append(
                    Vulnerability(
                        id=v["id"],
                        severity=v["severity"],
                        cvss=v["cvss"],
                        fixed_versions=v["fixed"],
                        url=v["url"],
                        source=v["source"],
                    ),
                )

    props = _props(md.get("properties"))
    phases = [p.get("phase") for p in md.get("lifecycles", []) or [] if isinstance(p, dict)]
    tools_raw = md.get("tools")
    tool_items = tools_raw.get("components", []) if isinstance(tools_raw, dict) else (tools_raw or [])
    meta = DocumentMeta(
        name=(root.name if root else "") or "sbom",
        version=root.version if root else None,
        serial=doc.get("serialNumber"),
        bom_version=doc.get("version", 1) or 1,
        timestamp=md.get("timestamp"),
        authors=[a["name"] for a in md.get("authors", []) or [] if a.get("name")],
        tools=[
            {"name": t.get("name", ""), "version": t.get("version", "")}
            for t in tool_items
            if isinstance(t, dict) and t.get("name")
        ],
        manufacturer=(md.get("manufacturer") or {}).get("name"),
        lifecycle=props.get(PROPERTY_PREFIX + "lifecycle")
        or (_PHASE_TO_LIFECYCLE.get(phases[0], "") if phases else ""),
        level=props.get(PROPERTY_PREFIX + "sbom-level", ""),
        has_nested_dependencies=any(src != (root.ref if root else None) and bool(dsts) for src, dsts in edges.items()),
        vulnerability_analysis=analysed,
    )
    return SbomModel(meta=meta, components=components, root=root)


# ── SPDX ────────────────────────────────────────────────────────────────────


def model_from_spdx(doc: Dict[str, Any]) -> SbomModel:
    relationships = doc.get("relationships", []) or []
    root_id = next(
        (
            r["relatedSpdxElement"]
            for r in relationships
            if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
        ),
        None,
    )
    packages = [p for p in doc.get("packages", []) or [] if p.get("name")]
    by_id: Dict[str, Component] = {}
    root: Optional[Component] = None
    components: List[Component] = []
    for p in packages:
        purl = next(
            (r.get("referenceLocator") for r in p.get("externalRefs", []) or [] if r.get("referenceType") == "purl"),
            None,
        )
        sup = p.get("supplier")
        lic = [
            x for x in (p.get("licenseDeclared"), p.get("licenseConcluded")) if x and x not in ("NOASSERTION", "NONE")
        ]
        spdx_id = p.get("SPDXID", p["name"])
        comp = Component(
            ref=spdx_id,
            name=p["name"],
            version=p.get("versionInfo"),
            type=(p.get("primaryPackagePurpose") or "library").lower(),
            purl=purl,
            description=p.get("description") or p.get("summary"),
            supplier=sup.split(":", 1)[-1].strip() if sup and sup != "NOASSERTION" else None,
            licenses=lic[:1],
            hashes=[{"alg": c["algorithm"], "content": c["checksumValue"]} for c in p.get("checksums", []) or []],
            release_date=p.get("releaseDate"),
            end_of_life_date=p.get("validUntilDate"),
            is_root=spdx_id == root_id,
            # SPDX 2.3 has no vulnerability section, so a scanner SPDX says nothing about them.
            vulnerabilities_checked=False,
        )
        by_id[spdx_id] = comp
        if comp.is_root:
            root = comp
        else:
            components.append(comp)
    edges: Dict[str, List[str]] = {}
    for r in relationships:
        if (
            r.get("relationshipType") == "DEPENDS_ON"
            and r.get("spdxElementId") in by_id
            and r.get("relatedSpdxElement") in by_id
        ):
            edges.setdefault(r["spdxElementId"], []).append(r["relatedSpdxElement"])
    for src, dsts in edges.items():
        by_id[src].depends_on = dsts
    stats = _depth_and_dependents(root.ref if root else None, edges)
    for c in by_id.values():
        c.depth = stats["depth"].get(c.ref, 2)
        c.dependents = stats["indegree"].get(c.ref, 0)

    ci = doc.get("creationInfo") or {}
    doc_props = {}
    for a in doc.get("annotations", []) or []:
        if "=" in a.get("comment", ""):
            k, _, v = a["comment"].partition("=")
            doc_props[k] = v
    authors = [c.split(":", 1)[1].strip() for c in ci.get("creators", []) if c.startswith(("Person:", "Organization:"))]
    tools = []
    for c in ci.get("creators", []):
        if c.startswith("Tool:"):
            name, _, ver = c.split(":", 1)[1].strip().rpartition("-")
            tools.append({"name": name or c.split(":", 1)[1].strip(), "version": ver if name else ""})
    meta = DocumentMeta(
        name=doc.get("name", "sbom"),
        serial=doc.get("documentNamespace"),
        timestamp=ci.get("created"),
        authors=authors,
        tools=tools,
        lifecycle=doc_props.get(PROPERTY_PREFIX + "lifecycle", ""),
        level=doc_props.get(PROPERTY_PREFIX + "sbom-level", ""),
        has_nested_dependencies=any(src != root_id for src in edges),
        vulnerability_analysis=False,
    )
    return SbomModel(meta=meta, components=components, root=root)
