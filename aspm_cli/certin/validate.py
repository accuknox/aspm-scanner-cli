"""CERT-In SBOM data-field conformance check over a CycloneDX or SPDX document."""

from __future__ import annotations

from typing import Any, Dict, List

from collections import Counter

from .normalize import NormDoc, normalize_document
from .rules import (
    CONFORMANT,
    DECLARED_UNKNOWN,
    MISSING,
    NON_CONFORMANT,
    PARTIAL,
    POPULATED_STATES,
    component_fields,
    document_fields,
    load_rules,
)

STATUS_LABEL = {
    CONFORMANT: "Conformant",
    PARTIAL: "Partially conformant",
    NON_CONFORMANT: "Non-conformant",
}
EXAMPLE_LIMIT = 5


def validate_normalized(norm: NormDoc) -> Dict[str, Any]:
    rules = load_rules()
    comps = norm.components
    field_reports: List[Dict[str, Any]] = []
    hard_fail = False
    soft_fail = False
    scored_total = scored_populated = scored_declared = 0

    for rule in component_fields():
        rid = rule["id"]
        optional = bool(rule.get("optional"))
        counts = Counter()
        reasons: Counter = Counter()
        examples: List[str] = []
        for comp in comps:
            fv = comp.fields.get(rid)
            state = fv.state if fv else MISSING
            if state == DECLARED_UNKNOWN and not rule.get("allow_unknown", True):
                state = MISSING
            counts[state] += 1
            if state == DECLARED_UNKNOWN and fv:
                reasons[fv.reason or "unspecified"] += 1
            if state == MISSING and len(examples) < EXAMPLE_LIMIT:
                examples.append(comp.name or comp.ref)
        populated = counts["present"] + counts["derived"]
        declared = counts[DECLARED_UNKNOWN]
        missing = counts[MISSING]
        if optional:
            status = "not_scored"
        elif missing:
            status = "fail"
            if rule.get("allow_unknown", True):
                soft_fail = True
            else:
                hard_fail = True
        else:
            status = "pass"
        if not optional:
            scored_total += len(comps)
            scored_populated += populated
            scored_declared += declared
        field_reports.append(
            {
                "id": rid,
                "clause": rule["clause"],
                "label": rule["label"],
                "scope": "component",
                "optional": optional,
                "status": status,
                "populated": populated,
                "declared_unknown": declared,
                "missing": missing,
                "total": len(comps),
                "unknown_reasons": dict(reasons),
                "examples_missing": examples,
            }
        )

    document_reports: List[Dict[str, Any]] = []
    for rule in document_fields():
        fv = norm.document.get(rule["id"])
        ok = bool(fv and fv.state in POPULATED_STATES)
        if not ok:
            hard_fail = True
        document_reports.append(
            {
                "id": rule["id"],
                "clause": rule["clause"],
                "label": rule["label"],
                "scope": "document",
                "status": "pass" if ok else "fail",
            }
        )

    checks: List[Dict[str, Any]] = []

    def check(cid: str, ok: bool, detail: str, blocking: bool = True) -> None:
        nonlocal hard_fail
        checks.append({"id": cid, "status": "pass" if ok else ("fail" if blocking else "advisory"), "detail": detail})
        if blocking and not ok:
            hard_fail = True

    check("format", norm.format in rules["formats"], "Document format is {}".format(norm.format))
    check("components", len(comps) > 0, "{} component(s) listed".format(len(comps)))
    check("spec_version", bool(norm.spec_version), "Specification version {}".format(norm.spec_version or "missing"))
    check(
        "lifecycle",
        bool(norm.lifecycle),
        "SBOM lifecycle class {}".format(norm.lifecycle or "not recorded"),
        blocking=False,
    )
    check("level", bool(norm.level), "SBOM level {}".format(norm.level or "not recorded"), blocking=False)

    status = NON_CONFORMANT if hard_fail else (PARTIAL if soft_fail else CONFORMANT)
    report: Dict[str, Any] = {
        "profile": rules["profile"],
        "guideline": rules["guideline"],
        "validator_version": rules["validator_version"],
        "pass_rule_note": rules["pass_rule_note"],
        "applicability_note": rules["applicability_note"],
        "format": norm.format,
        "spec_version": norm.spec_version,
        "export_profile": norm.profile,
        "components": len(comps),
        "status": status,
        "status_label": STATUS_LABEL[status],
        "populated_pct": round(100.0 * scored_populated / scored_total, 1) if scored_total else 0.0,
        "declared_unknown_pct": round(100.0 * scored_declared / scored_total, 1) if scored_total else 0.0,
        "fields": field_reports,
        "document": document_reports,
        "checks": checks,
    }
    if norm.attestation:
        claimed = norm.attestation.get("status")
        report["attestation"] = {"claimed": claimed, "recomputed": status, "matches": claimed == status}
    return report


def validate_document(content: Any) -> Dict[str, Any]:
    """Validate parsed JSON, a JSON string, or SPDX tag-value text."""
    return validate_normalized(normalize_document(content))


def attestation_properties(report: Dict[str, Any]) -> Dict[str, str]:
    """Key/value pairs embedded in the file (prefix ``accuknox:cert-in:`` is added by the exporter)."""
    return {
        "profile": report["profile"],
        "status": report["status"],
        "populated-pct": str(report["populated_pct"]),
        "declared-unknown-pct": str(report["declared_unknown_pct"]),
        "components": str(report["components"]),
        "validator-version": report["validator_version"],
        "claim": "Self-assessed by AccuKnox against the CERT-In SBOM minimum data fields; not a CERT-In certification",
    }
