"""Shared pieces of the exporters: derivation over a whole SBOM, license and date handling."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import re
from datetime import datetime, timezone

from .derive import FieldValue, _license_rank, derive_component, unknown
from .model import SbomModel
from .rules import NOASSERTION

FULL = "full"
PUBLIC = "public"
PROFILES = (FULL, PUBLIC)

WITHHELD = "withheld-in-public-profile"

Derived = Dict[str, Dict[str, FieldValue]]  # component ref -> field id -> value


def derive_all(sbom: SbomModel, profile: str = FULL) -> Derived:
    """Derive every component's CERT-In fields; ``public`` withholds vulnerability data."""
    out: Derived = {}
    for comp in [c for c in ([sbom.root] if sbom.root else []) + sbom.components]:
        if profile == PUBLIC:
            vulns = comp.vulnerabilities
            comp.vulnerabilities = []  # criticality in the public view must not leak them
            fields = derive_component(comp, sbom.meta)
            comp.vulnerabilities = vulns
            fields["vulnerabilities"] = unknown(WITHHELD)
            fields["patch_status"] = unknown(WITHHELD)
        else:
            fields = derive_component(comp, sbom.meta)
        out[comp.ref] = fields
    return out


# ── time ────────────────────────────────────────────────────────────────────


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_iso_z(value: Optional[str]) -> Optional[str]:
    """Normalise a date or datetime string to ``YYYY-MM-DDThh:mm:ssZ`` (UTC)."""
    if not value:
        return None
    text = str(value).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return text + "T00:00:00Z"
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── licenses ────────────────────────────────────────────────────────────────

_EXPR_SPLIT = re.compile(r"\s+(?:AND|OR|WITH)\s+|[()]", re.IGNORECASE)


def _is_known_id(token: str) -> bool:
    return _license_rank(token) is not None


def license_kind(lic: str) -> str:
    """``id`` for one recognised SPDX id, ``expression`` for a compound one, else ``name``."""
    text = lic.strip()
    if re.search(r"\s+(AND|OR|WITH)\s+|[()]", text, re.IGNORECASE):
        tokens = [t.strip() for t in _EXPR_SPLIT.split(text) if t and t.strip()]
        return (
            "expression" if tokens and all(_is_known_id(t) or t.startswith("LicenseRef-") for t in tokens) else "name"
        )
    return "id" if _is_known_id(text) else "name"


def license_ref(name: str) -> str:
    return "LicenseRef-" + re.sub(r"[^A-Za-z0-9.\-]+", "-", name).strip("-")[:60]


# ── hashes ──────────────────────────────────────────────────────────────────

_CDX_ALGS = {
    "MD5": "MD5", "SHA1": "SHA-1", "SHA-1": "SHA-1", "SHA256": "SHA-256", "SHA-256": "SHA-256",
    "SHA384": "SHA-384", "SHA-384": "SHA-384", "SHA512": "SHA-512", "SHA-512": "SHA-512",
    "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512",
    "BLAKE2B-256": "BLAKE2b-256", "BLAKE2B-384": "BLAKE2b-384", "BLAKE2B-512": "BLAKE2b-512", "BLAKE3": "BLAKE3",
}  # fmt: skip
_SPDX_ALGS = {v: k for k, v in {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "MD5": "MD5", "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512"}.items()}  # fmt: skip


def cdx_alg(alg: str) -> Optional[str]:
    return _CDX_ALGS.get(
        (alg or "")
        .upper()
        .replace("_", "-")
        .replace("SHA-1", "SHA1")
        .replace("SHA-256", "SHA256")
        .replace("SHA-384", "SHA384")
        .replace("SHA-512", "SHA512")
    ) or _CDX_ALGS.get((alg or "").upper())


def spdx_alg(alg: str) -> Optional[str]:
    cdx = cdx_alg(alg)
    return _SPDX_ALGS.get(cdx) if cdx else None


# ── properties shared by both formats ───────────────────────────────────────

# rule id -> property key (value comes from the derived field)
PROPERTY_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("component_origin", "origin"),
    ("patch_status", "patch-status"),
    ("criticality", "criticality"),
    ("usage_restrictions", "usage-restrictions"),
    ("executable_property", "executable"),
    ("archive_property", "archive"),
    ("structured_property", "structured"),
    ("unique_identifier", "unique-id"),
)
# rule ids whose value has a native slot in the formats (so only unknowns need a marker)
NATIVE_FIELDS = (
    "component_version", "component_description", "component_supplier", "component_license", "checksums",
    "release_date", "end_of_life_date", "component_dependencies", "vulnerabilities",
)  # fmt: skip


def component_properties(fields: Dict[str, FieldValue]) -> List[Tuple[str, str]]:
    """``(key, value)`` pairs, without the ``certin:`` prefix, for non-native fields and unknown markers."""
    props: List[Tuple[str, str]] = []
    for rule_id, key in PROPERTY_FIELDS:
        fv = fields.get(rule_id)
        if fv and fv.populated:
            props.append((key, str(fv.value)))
        elif fv:
            props.append(("unknown:" + rule_id, fv.reason))
    for rule_id in NATIVE_FIELDS:
        fv = fields.get(rule_id)
        if fv and not fv.populated and fv.state != "missing":
            props.append(("unknown:" + rule_id, fv.reason))
    return props


def spdx_supplier(value: Optional[str]) -> str:
    return "Organization: " + value if value else NOASSERTION
