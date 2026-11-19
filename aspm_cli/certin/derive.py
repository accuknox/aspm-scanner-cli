"""Automatic derivation of the CERT-In minimum data fields for one component.

Every function here is pure: the same component always yields the same value,
and nothing is looked up over the network or in a database. Values that need a
lookup (release date, end-of-life date, supplier fallback, latest version) are
filled onto :class:`~xbom.certin.model.Component` by the caller before deriving.

Where a field cannot be derived the result is ``declared_unknown`` with a short
reason code, never a guess.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote

from .model import Component, DocumentMeta
from .rules import DECLARED_UNKNOWN, DERIVED, MISSING, NOASSERTION, PRESENT

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# purl types that name a public package registry.
PUBLIC_REGISTRY_TYPES = {
    "npm", "pypi", "maven", "gem", "cargo", "golang", "nuget", "composer", "pub",
    "hex", "cocoapods", "conan", "swift", "deb", "rpm", "apk", "alpm", "conda",
    "cran", "hackage", "bitbucket", "github", "gitlab",
}  # fmt: skip

# purl type -> (archive description, structured/manifest description)
ECOSYSTEM_ARCHIVE = {
    "maven": "JAR/WAR archive",
    "pypi": "wheel/sdist archive",
    "npm": "npm tarball (.tgz)",
    "gem": ".gem archive",
    "cargo": ".crate archive",
    "nuget": ".nupkg archive",
    "golang": "Go module zip",
    "composer": "zip archive",
    "pub": "tar.gz archive",
    "hex": "tar archive",
    "deb": ".deb archive",
    "rpm": ".rpm archive",
    "apk": ".apk archive",
    "conda": "conda archive",
    "oci": "OCI image layers (tar)",
    "docker": "OCI image layers (tar)",
}
MANIFEST_NAME = {
    "maven": "pom.xml",
    "pypi": "pyproject/setup metadata",
    "npm": "package.json",
    "gem": "gemspec",
    "cargo": "Cargo.toml",
    "nuget": ".nuspec",
    "golang": "go.mod",
    "composer": "composer.json",
    "pub": "pubspec.yaml",
    "hex": "mix.exs",
    "deb": "control file",
    "rpm": "RPM header",
    "apk": ".PKGINFO",
}
EXECUTABLE_TYPES = {"application", "container", "firmware", "operating-system", "device"}
LIBRARY_TYPES = {"library", "framework"}
EXECUTABLE_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".sh", ".bat", ".cmd", ".com", ".msi", ".jar", ".war"}
STRUCTURED_EXT = {".json", ".xml", ".yaml", ".yml", ".toml", ".csv", ".ini", ".properties", ".cfg", ".conf"}


@dataclass
class FieldValue:
    value: Any
    state: str  # present / derived / declared_unknown / missing
    reason: str = ""  # reason code when declared_unknown
    source: str = ""  # where the value came from

    @property
    def populated(self) -> bool:
        return self.state in (PRESENT, DERIVED)


def unknown(reason: str) -> FieldValue:
    return FieldValue(NOASSERTION, DECLARED_UNKNOWN, reason)


# ── purl ────────────────────────────────────────────────────────────────────


@dataclass
class ParsedPurl:
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: Dict[str, str]
    subpath: str


def parse_purl(purl: Optional[str]) -> Optional[ParsedPurl]:
    """Parse ``pkg:type/ns/name@ver?q=v#sub``; None when it is not a purl."""
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl[4:].lstrip("/")
    subpath = ""
    if "#" in rest:
        rest, subpath = rest.split("#", 1)
    quals: Dict[str, str] = {}
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        for pair in qs.split("&"):
            if "=" in pair:
                key, _, val = pair.partition("=")
                quals[unquote(key).lower()] = unquote(val)
    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
    if "/" not in rest:
        return None
    ptype, _, path = rest.partition("/")
    namespace, _, name = path.rpartition("/")
    if not ptype or not name:
        return None
    return ParsedPurl(ptype.lower(), unquote(namespace), unquote(name), unquote(version), quals, unquote(subpath))


# ── unique identifier (4.2.21, Table 3) ─────────────────────────────────────

_ID_QUALIFIERS = ("arch", "os", "distro", "type", "classifier")


def _encode_segment(text: str) -> str:
    return quote(re.sub(r"\s+", "", text or ""), safe="-._~")


def build_unique_id(supplier: Optional[str], name: str, version: Optional[str], purl: Optional[str]) -> str:
    """``pkg:supplier/<Org>/<Name>@<Version>?<qualifiers>#<subpath>``.

    The guideline does not say what to do when the supplier is unknown; the
    supplier segment is then the literal ``NOASSERTION``.
    """
    org = _encode_segment(supplier) if supplier and supplier != NOASSERTION else NOASSERTION
    out = "pkg:supplier/{}/{}".format(org, _encode_segment(name))
    if version:
        out += "@" + _encode_segment(version)
    parsed = parse_purl(purl)
    if parsed:
        quals = [(k, parsed.qualifiers[k]) for k in _ID_QUALIFIERS if parsed.qualifiers.get(k)]
        if quals:
            out += "?" + "&".join("{}={}".format(k, quote(v, safe="-._~")) for k, v in quals)
        if parsed.subpath:
            out += "#" + quote(parsed.subpath, safe="-._~/")
    return out


# ── licenses → usage restrictions ───────────────────────────────────────────

_PERMISSIVE = re.compile(
    r"^(MIT|MIT-0|Apache-.*|BSD-.*|ISC|Unlicense|0BSD|Zlib|CC0-1\.0|BSL-1\.0|PostgreSQL|Python-2\.0|PSF-.*|"
    r"X11|NCSA|WTFPL|Artistic-.*|BlueOak-.*|CC-BY-.*|JSON|curl|OpenSSL|HPND|libpng.*|Libpng|FTL|IJG)$",
    re.IGNORECASE,
)
_WEAK = re.compile(r"^(LGPL-.*|MPL-.*|EPL-.*|CDDL-.*|CPL-.*|OSL-.*|EUPL-.*|CC-BY-SA-.*|Ms-RL|APSL-.*)$", re.IGNORECASE)
_STRONG = re.compile(r"^(GPL-.*|GPL|OFL-.*)$", re.IGNORECASE)
_NETWORK = re.compile(r"^(AGPL-.*|SSPL-.*|OSL-3\.0|RPL-.*)$", re.IGNORECASE)
_PROPRIETARY = re.compile(r"(proprietary|commercial|eula|all rights reserved|licenseref-|custom)", re.IGNORECASE)

_RANK_TEXT = {
    0: "Attribution and license notice required; no copyleft obligation",
    1: "Weak copyleft: changes to the component must be shared under the same license",
    2: "Strong copyleft: derivative works must be released under the same license",
    3: "Network copyleft: source must be offered to users who interact with it over a network",
}


def _license_rank(token: str) -> Optional[int]:
    base = token.strip().rstrip("+")
    base = (
        re.sub(r"-(only|or-later)$", "", base, flags=re.IGNORECASE)
        if base.upper().startswith(("GPL", "AGPL", "LGPL"))
        else base
    )
    if _NETWORK.match(base):
        return 3
    if _STRONG.match(base):
        return 2
    if _WEAK.match(base):
        return 1
    if _PERMISSIVE.match(base):
        return 0
    return None


def classify_licenses(licenses: List[str]) -> Tuple[Optional[int], bool]:
    """Return ``(rank, proprietary)`` over a component's license strings.

    Multiple entries are alternatives in practice (scanners list each detected
    license), so the least restrictive known rank wins; within one expression
    ``OR`` takes the least restrictive and ``AND`` the most restrictive.
    """
    ranks: List[int] = []
    proprietary = False
    for lic in licenses:
        if _PROPRIETARY.search(lic):
            proprietary = True
            continue
        rank = _expression_rank(lic)
        if rank is not None:
            ranks.append(rank)
    return (min(ranks) if ranks else None), proprietary


def _expression_rank(expr: str) -> Optional[int]:
    cleaned = expr.replace("(", " ").replace(")", " ")
    cleaned = re.sub(r"\s+WITH\s+\S+", "", cleaned, flags=re.IGNORECASE)
    or_parts = re.split(r"\s+OR\s+", cleaned, flags=re.IGNORECASE)
    or_ranks: List[int] = []
    for part in or_parts:
        and_ranks = [_license_rank(t) for t in re.split(r"\s+AND\s+", part.strip(), flags=re.IGNORECASE) if t.strip()]
        if and_ranks and all(r is not None for r in and_ranks):
            or_ranks.append(max(and_ranks))  # type: ignore[type-var]
    return min(or_ranks) if or_ranks else None


def derive_usage_restrictions(c: Component) -> FieldValue:
    if not c.licenses:
        return unknown("no-license-in-source")
    rank, proprietary = classify_licenses(c.licenses)
    names = ", ".join(c.licenses)
    if rank is not None:
        return FieldValue("{} ({})".format(_RANK_TEXT[rank], names), DERIVED, source="license-classification")
    if proprietary:
        return FieldValue(
            "Proprietary or custom license; see the license terms ({})".format(names),
            DERIVED,
            source="license-classification",
        )
    return unknown("license-not-classified")


# ── other fields ────────────────────────────────────────────────────────────


def derive_origin(c: Component) -> FieldValue:
    if c.is_root:
        return FieldValue("proprietary", DERIVED, source="subject-of-sbom")
    _, proprietary = classify_licenses(c.licenses)
    if proprietary:
        return FieldValue("third-party vendor", DERIVED, source="license-text")
    parsed = parse_purl(c.purl)
    if parsed and parsed.type in PUBLIC_REGISTRY_TYPES:
        return FieldValue("open-source", DERIVED, source="purl-registry:" + parsed.type)
    return unknown("origin-undetermined")


def _bump(level: str) -> str:
    idx = SEVERITY_ORDER.index(level)
    return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]


def derive_criticality(c: Component) -> FieldValue:
    vuln_sev = [v.severity.lower() for v in c.vulnerabilities if v.severity and v.severity.lower() in SEVERITY_ORDER]
    if any(v.known_exploited for v in c.vulnerabilities):
        level = "critical"
    elif vuln_sev:
        level = max(vuln_sev, key=SEVERITY_ORDER.index)
    elif c.is_root or c.type in EXECUTABLE_TYPES or c.depth <= 1:
        level = "medium"
    else:
        level = "low"
    if c.dependents > 5:
        level = _bump(level)
    return FieldValue(level, DERIVED, source="criticality-formula")


def derive_patch_status(c: Component) -> FieldValue:
    if not c.vulnerabilities:
        if not c.vulnerabilities_checked:
            return unknown("vulnerability-lookup-not-run" if c.purl else "no-purl-for-vulnerability-lookup")
        if c.latest_version and c.version:
            if c.latest_version == c.version:
                return FieldValue("Up to date", DERIVED, source="registry")
            return FieldValue("Update available: {}".format(c.latest_version), DERIVED, source="registry")
        return FieldValue("None reported", DERIVED, source="vulnerability-lookup")
    fixed = sorted({f for v in c.vulnerabilities for f in v.fixed_versions})
    with_fix = [v for v in c.vulnerabilities if v.fixed_versions]
    if len(with_fix) == len(c.vulnerabilities):
        return FieldValue(
            "Patch available: upgrade to {}".format(", ".join(fixed[:3])), DERIVED, source="vulnerability-lookup"
        )
    if with_fix:
        return FieldValue("Patch available for some vulnerabilities", DERIVED, source="vulnerability-lookup")
    return FieldValue("No patch available", DERIVED, source="vulnerability-lookup")


def _ext(name: str) -> str:
    m = re.search(r"(\.[A-Za-z0-9]+)$", name or "")
    return m.group(1).lower() if m else ""


def derive_executable(c: Component) -> FieldValue:
    ctype = (c.type or "").lower()
    if ctype in EXECUTABLE_TYPES:
        return FieldValue("Yes - {} is run directly".format(ctype), DERIVED, source="component-type")
    if ctype in LIBRARY_TYPES:
        return FieldValue(
            "No - {} loaded by a host application, not run on its own".format(ctype), DERIVED, source="component-type"
        )
    if ctype == "file":
        ext = _ext(c.name)
        if ext in EXECUTABLE_EXT:
            return FieldValue("Yes - file with executable extension {}".format(ext), DERIVED, source="file-extension")
        if ext:
            return FieldValue("No - file type {} is not executable".format(ext), DERIVED, source="file-extension")
    return unknown("component-type-unclear")


def derive_archive(c: Component) -> FieldValue:
    parsed = parse_purl(c.purl)
    if parsed and parsed.type in ECOSYSTEM_ARCHIVE:
        if parsed.type == "maven" and parsed.qualifiers.get("type") == "pom":
            return FieldValue("No - POM descriptor, not an archive", DERIVED, source="purl")
        return FieldValue(
            "Yes - distributed as {}".format(ECOSYSTEM_ARCHIVE[parsed.type]), DERIVED, source="purl-type:" + parsed.type
        )
    if (c.type or "").lower() == "container":
        return FieldValue("Yes - distributed as OCI image layers (tar)", DERIVED, source="component-type")
    if (c.type or "").lower() == "file":
        ext = _ext(c.name)
        if ext in {".zip", ".tar", ".gz", ".tgz", ".jar", ".war", ".whl", ".rar", ".7z", ".bz2", ".xz"}:
            return FieldValue("Yes - archive file {}".format(ext), DERIVED, source="file-extension")
        if ext:
            return FieldValue("No - file type {} is not an archive".format(ext), DERIVED, source="file-extension")
    return unknown("distribution-format-unknown")


def derive_structured(c: Component) -> FieldValue:
    parsed = parse_purl(c.purl)
    if parsed and parsed.type in MANIFEST_NAME:
        return FieldValue(
            "Yes - package metadata in {} ({})".format(MANIFEST_NAME[parsed.type], parsed.type),
            DERIVED,
            source="purl-type:" + parsed.type,
        )
    ext = _ext(c.name)
    if (c.type or "").lower() in ("data", "file") and ext:
        if ext in STRUCTURED_EXT:
            return FieldValue("Yes - {} structured data".format(ext.lstrip(".")), DERIVED, source="file-extension")
        return FieldValue("No - file type {} has no defined structure".format(ext), DERIVED, source="file-extension")
    return unknown("data-format-unknown")


def derive_dependencies(c: Component, meta: DocumentMeta) -> FieldValue:
    if c.depends_on:
        return FieldValue(list(c.depends_on), PRESENT, source="sbom")
    if not meta.has_nested_dependencies and not c.is_root:
        return unknown("flat-dependency-graph")
    return FieldValue([], PRESENT, source="sbom")


# ── entry point ─────────────────────────────────────────────────────────────


def derive_component(c: Component, meta: DocumentMeta) -> Dict[str, FieldValue]:
    """All per-component CERT-In fields for ``c``, keyed by rule id."""
    out: Dict[str, FieldValue] = {}
    out["component_name"] = FieldValue(c.name, PRESENT, source="sbom") if c.name else FieldValue(None, MISSING)
    out["component_version"] = (
        FieldValue(c.version, PRESENT, source="sbom") if c.version else unknown("no-version-in-source")
    )
    out["component_description"] = (
        FieldValue(c.description, PRESENT, source=c.extra.get("description_source", "sbom"))
        if c.description
        else unknown("description-not-in-source")
    )
    out["component_supplier"] = (
        FieldValue(c.supplier, PRESENT, source=c.extra.get("supplier_source", "sbom"))
        if c.supplier
        else unknown("supplier-not-in-source")
    )
    out["component_license"] = (
        FieldValue(list(c.licenses), PRESENT, source="sbom") if c.licenses else unknown("no-license-in-source")
    )
    out["component_origin"] = derive_origin(c)
    out["component_dependencies"] = derive_dependencies(c, meta)
    if c.vulnerabilities or c.vulnerabilities_checked:
        out["vulnerabilities"] = FieldValue([v.id for v in c.vulnerabilities], DERIVED, source="vulnerability-lookup")
    else:
        out["vulnerabilities"] = unknown(
            "vulnerability-lookup-not-run" if c.purl else "no-purl-for-vulnerability-lookup"
        )
    out["patch_status"] = derive_patch_status(c)
    out["release_date"] = (
        FieldValue(c.release_date, DERIVED, source="registry-metadata")
        if c.release_date
        else unknown("release-date-not-found")
    )
    out["end_of_life_date"] = (
        FieldValue(c.end_of_life_date, DERIVED, source="registry-metadata")
        if c.end_of_life_date
        else unknown("end-of-life-not-published")
    )
    out["criticality"] = derive_criticality(c)
    out["usage_restrictions"] = derive_usage_restrictions(c)
    out["checksums"] = FieldValue(list(c.hashes), PRESENT, source="sbom") if c.hashes else unknown("no-hash-in-source")
    out["executable_property"] = derive_executable(c)
    out["archive_property"] = derive_archive(c)
    out["structured_property"] = derive_structured(c)
    out["unique_identifier"] = FieldValue(
        build_unique_id(c.supplier, c.name, c.version, c.purl), DERIVED, source="supplier+name+version"
    )
    # Overrides carried on the component win (round-trips of already-derived values).
    return out
