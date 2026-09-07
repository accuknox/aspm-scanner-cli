"""Merge normalized Syft licenses onto matching Trivy CycloneDX components."""

import json
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

from aspm_cli.utils.sbom import (
    DOCKER_WORKDIR,
    FILESYSTEM_SUBCOMMANDS,
    normalize_filesystem_args_for_docker,
    parse_trivy_subcommand,
    scan_target_from_command,
)

SYFT_SBOM_FILENAME = ".accuknox-syft-sbom.json"

LICENSE_ALIASES = {
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause",
}


def should_enrich_filesystem_licenses(command: str, enrich_licenses: bool) -> bool:
    """True when --enrich-licenses applies to a filesystem/fs SBOM command."""
    if not enrich_licenses:
        return False
    return parse_trivy_subcommand(command) in FILESYSTEM_SUBCOMMANDS


def syft_scan_source(command: str, container_mode: bool) -> str:
    """Syft ``dir:`` source for the same tree Trivy scanned."""
    target = scan_target_from_command(command) or "."
    if container_mode:
        subcommand = parse_trivy_subcommand(command) or "filesystem"
        normalized = normalize_filesystem_args_for_docker([subcommand, target])
        target = normalized[1] if len(normalized) > 1 else DOCKER_WORKDIR
    return f"dir:{target}"


def normalize_license_id(value: Optional[str]) -> Optional[str]:
    """Drop UNKNOWN/hash ids; map common aliases to SPDX; keep expressions."""
    if not value:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if stripped.upper() == "UNKNOWN":
        return None
    if stripped.lower().startswith("sha256:"):
        return None
    alias = LICENSE_ALIASES.get(stripped.lower())
    if alias:
        return alias
    return stripped


def _is_spdx_expression(value: str) -> bool:
    upper = f" {value.upper()} "
    return " AND " in upper or " OR " in upper or " WITH " in upper


def _license_entry(normalized: str) -> Dict[str, Any]:
    if _is_spdx_expression(normalized):
        return {"expression": normalized}
    return {"license": {"id": normalized}}


def _raw_license_texts(item: Dict[str, Any]) -> Iterable[Tuple[str, bool]]:
    expression = item.get("expression")
    if isinstance(expression, str):
        yield expression, True
        return
    license_obj = item.get("license")
    if isinstance(license_obj, dict):
        for key in ("id", "name"):
            value = license_obj.get(key)
            if isinstance(value, str) and value.strip() and normalize_license_id(value):
                yield value, False
                return


def normalized_license_entries(component: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return CycloneDX license choices after alias/hash filtering."""
    raw = component.get("licenses")
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        for text, from_expression in _raw_license_texts(item):
            normalized = normalize_license_id(text)
            if not normalized:
                continue
            if from_expression or _is_spdx_expression(normalized):
                key = ("expression", normalized)
                entry = {"expression": normalized}
            else:
                key = ("id", normalized)
                entry = _license_entry(normalized)
            if key in seen:
                continue
            seen.add(key)
            out.append(entry)
    return out


def _component_has_licenses(component: Dict[str, Any]) -> bool:
    licenses = component.get("licenses")
    return isinstance(licenses, list) and len(licenses) > 0


def _match_keys(component: Dict[str, Any]) -> List[Tuple[str, str]]:
    keys: List[Tuple[str, str]] = []
    purl = component.get("purl")
    if isinstance(purl, str) and purl.strip():
        keys.append(("purl", purl.strip()))
    name = component.get("name")
    version = component.get("version")
    if isinstance(name, str) and name.strip() and isinstance(version, str) and version.strip():
        keys.append(("nv", f"{name.strip()}@{version.strip()}"))
    return keys


def _index_syft_licenses(syft_data: Dict[str, Any]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    index: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    components = syft_data.get("components")
    if not isinstance(components, list):
        return index
    for component in components:
        if not isinstance(component, dict):
            continue
        licenses = normalized_license_entries(component)
        if not licenses:
            continue
        for key in _match_keys(component):
            index.setdefault(key, licenses)
    return index


def merge_syft_licenses_into_trivy(
    trivy_data: Dict[str, Any],
    syft_data: Dict[str, Any],
) -> Dict[str, int]:
    """
    Copy normalized Syft licenses onto Trivy components that have none.

    Match by purl, then name@version. Does not append Syft-only components
    and does not overwrite existing Trivy licenses.
    """
    index = _index_syft_licenses(syft_data)
    enriched = 0
    skipped_existing = 0
    unmatched = 0
    components = trivy_data.get("components")
    if not isinstance(components, list):
        return {"enriched": 0, "skipped_existing": 0, "unmatched": 0}

    for component in components:
        if not isinstance(component, dict):
            continue
        if _component_has_licenses(component):
            skipped_existing += 1
            continue
        matched: Optional[List[Dict[str, Any]]] = None
        for key in _match_keys(component):
            matched = index.get(key)
            if matched:
                break
        if not matched:
            unmatched += 1
            continue
        component["licenses"] = [dict(entry) for entry in matched]
        enriched += 1
    return {
        "enriched": enriched,
        "skipped_existing": skipped_existing,
        "unmatched": unmatched,
    }


def merge_syft_licenses_into_trivy_file(trivy_path: str, syft_path: str) -> Dict[str, int]:
    """Load both BOMs from disk, merge licenses, and rewrite the Trivy file."""
    with open(trivy_path, "r", encoding="utf-8") as handle:
        trivy_data = json.load(handle)
    with open(syft_path, "r", encoding="utf-8") as handle:
        syft_data = json.load(handle)
    if not isinstance(trivy_data, dict) or not isinstance(syft_data, dict):
        raise ValueError("SBOM files must contain CycloneDX JSON objects")
    stats = merge_syft_licenses_into_trivy(trivy_data, syft_data)
    with open(trivy_path, "w", encoding="utf-8") as handle:
        json.dump(trivy_data, handle, indent=2)
    return stats


def remove_syft_sbom_file(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
