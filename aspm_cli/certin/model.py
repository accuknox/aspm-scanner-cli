"""Format-neutral SBOM model the CERT-In exporters work from."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    id: str
    severity: str = ""  # critical / high / medium / low / unknown
    cvss: Optional[float] = None
    epss: Optional[float] = None
    known_exploited: bool = False
    fixed_versions: List[str] = field(default_factory=list)
    url: str = ""
    source: str = ""


@dataclass
class Component:
    ref: str
    name: str
    version: Optional[str] = None
    type: str = "library"
    purl: Optional[str] = None
    description: Optional[str] = None
    supplier: Optional[str] = None
    licenses: List[str] = field(default_factory=list)
    hashes: List[Dict[str, str]] = field(default_factory=list)  # {"alg", "content"}
    depends_on: List[str] = field(default_factory=list)  # refs
    release_date: Optional[str] = None
    end_of_life_date: Optional[str] = None
    latest_version: Optional[str] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    # False when no vulnerability lookup was possible for this component.
    vulnerabilities_checked: bool = False
    depth: int = 1  # 0 root, 1 direct, 2+ transitive
    dependents: int = 0
    is_root: bool = False
    # Optional pre-derived values by field id (used by round-trips and tests).
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DocumentMeta:
    name: str = ""
    version: Optional[str] = None
    serial: Optional[str] = None  # urn:uuid:... (CycloneDX) or namespace (SPDX)
    bom_version: int = 1
    timestamp: Optional[str] = None  # ISO-8601, document assembly time
    timestamp_is_ingest_fallback: bool = False
    authors: List[str] = field(default_factory=list)
    tools: List[Dict[str, str]] = field(default_factory=list)  # {"name", "version"}
    manufacturer: Optional[str] = None
    lifecycle: str = ""  # CERT-In: design/source/build/analyzed/deployed/runtime
    level: str = ""  # CERT-In: top/n/delivery/transitive/complete
    has_nested_dependencies: bool = True
    # True when vulnerability lookup ran for this SBOM (so a component with none is "none reported").
    vulnerability_analysis: bool = False
    # Source facts the document itself declared as unknown, e.g. {"unknown_dependencies": [...]}
    compositions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SbomModel:
    meta: DocumentMeta
    components: List[Component]
    root: Optional[Component] = None
