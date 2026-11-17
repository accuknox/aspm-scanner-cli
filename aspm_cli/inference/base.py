"""Shared types for source-based dependency inference.

Inference is for repositories whose dependency tracker (``conan.lock``, ``requirements.txt`` ...)
is missing. It only ever *reads* the scanned tree; it never writes into it.
"""
from __future__ import annotations

import abc
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

CONFIDENCE_A = "A"  # explicit manifest-like evidence with a resolved version
CONFIDENCE_B = "B"  # version sniffed from a vendored tree
CONFIDENCE_C = "C"  # name only (an #include, or a version constraint with no resolved version)

# Sources a dependency can come from. ``registry`` ones can be matched against advisories;
# ``git`` / ``vendored`` / ``include-only`` ones are listed but never looked up.
SOURCE_REGISTRY = "registry"
SOURCE_GIT = "git"
SOURCE_VENDORED = "vendored"
SOURCE_INCLUDE = "include-only"

PROP_PREFIX = "accuknox:"
LOOKUP_BLOCKED_PURL_TYPES = frozenset({"generic", "github", "gitlab", "bitbucket"})


def strip_url_credentials(url: str) -> str:
    """Drop ``user:token@`` from a URL so a private remote's credentials never reach the BOM."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if "@" in parts.netloc:
        netloc = parts.netloc.rsplit("@", 1)[1]
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return url


def normalize_dep_name(name: str) -> str:
    """Comparison key for names across Trivy/Syft/inference (case, Conan namespaces, lib prefix)."""
    text = (name or "").strip().lower()
    text = text.rsplit("/", 1)[-1]
    return re.sub(r"[^a-z0-9]+", "", text)


@dataclass
class InferredDep:
    name: str
    version: Optional[str]
    purl: str
    ecosystem: str
    confidence: str
    source: str
    evidence: List[str] = field(default_factory=list)
    repo_url: Optional[str] = None
    constraint: Optional[str] = None
    kind: str = "source-import"  # source-import | build-file | vendored | submodule

    @property
    def lookup_eligible(self) -> bool:
        """True when advisories can be matched: a resolved version on a registry-style purl."""
        if not self.version or self.source in (SOURCE_GIT, SOURCE_INCLUDE):
            return False
        purl_type = self.purl[4:].split("/", 1)[0] if self.purl.startswith("pkg:") else ""
        return purl_type not in LOOKUP_BLOCKED_PURL_TYPES

    def to_component(self) -> Dict[str, Any]:
        props = [
            {"name": PROP_PREFIX + "inferred", "value": self.kind},
            {"name": PROP_PREFIX + "confidence", "value": self.confidence},
            {"name": PROP_PREFIX + "source", "value": self.source},
        ]
        if self.evidence:
            props.append({"name": PROP_PREFIX + "evidence", "value": "; ".join(self.evidence[:3])})
        if self.constraint:
            props.append({"name": PROP_PREFIX + "version-constraint", "value": self.constraint})
        comp: Dict[str, Any] = {
            "type": "library",
            "bom-ref": self.purl or f"inferred:{self.ecosystem}:{self.name}",
            "name": self.name,
            "properties": props,
        }
        if self.version:
            comp["version"] = self.version
        if self.purl:
            comp["purl"] = self.purl
        if self.repo_url:
            comp["externalReferences"] = [{"type": "vcs", "url": strip_url_credentials(self.repo_url)}]
        return comp


@dataclass
class InferenceResult:
    deps: List[InferredDep] = field(default_factory=list)
    unresolved_includes: Dict[str, int] = field(default_factory=dict)
    files_scanned: int = 0

    def eligible(self) -> List[InferredDep]:
        return [d for d in self.deps if d.lookup_eligible]


class LanguageInferrer(abc.ABC):
    """One implementation per language; register in ``aspm_cli.inference.INFERRERS``."""

    language: str = ""

    @abc.abstractmethod
    def detect(self, root: str) -> bool:
        """Cheap check: does the tree contain sources of this language?"""

    @abc.abstractmethod
    def infer(self, root: str, existing_names: Optional[set] = None) -> InferenceResult:
        """Return dependencies found from sources/build files, skipping ``existing_names`` (normalized)."""
