"""CLI glue for the CERT-In SBOM fields: author, lifecycle, finalising the file, reporting."""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, Optional, Tuple

from colorama import Fore

from aspm_cli.certin.augment import augment_cyclonedx, augment_spdx
from aspm_cli.certin.rules import CONFORMANT
from aspm_cli.certin.validate import validate_document
from aspm_cli.utils.logger import Logger

SBOM_FORMATS = ("cyclonedx", "spdx")
TRIVY_FORMAT = {"cyclonedx": "cyclonedx", "spdx": "spdx-json"}
DEFAULT_AUTHOR = "AccuKnox ASPM Scanner"

# CI variables that name who triggered the run, most specific first.
_CI_IDENTITY_VARS = (
    "GITLAB_USER_EMAIL",
    "BUILD_REQUESTEDFOREMAIL",
    "GITHUB_ACTOR",
    "GITLAB_USER_LOGIN",
    "BUILD_REQUESTEDFOR",
    "CIRCLE_USERNAME",
    "BUILD_USER",
)

_STATUS_COLOR = {"conformant": Fore.GREEN, "partially_conformant": Fore.YELLOW, "non_conformant": Fore.RED}


def resolve_sbom_author(cli_value: Optional[str] = None) -> str:
    """SBOM author: --sbom-author, ACCUKNOX_SBOM_AUTHOR, the CI actor, git identity, then the tool."""
    if cli_value:
        return cli_value
    if os.environ.get("ACCUKNOX_SBOM_AUTHOR"):
        return os.environ["ACCUKNOX_SBOM_AUTHOR"]
    for name in _CI_IDENTITY_VARS:
        if os.environ.get(name):
            return os.environ[name]
    try:
        email = subprocess.run(
            ["git", "config", "user.email"], capture_output=True, text=True, timeout=5, check=False
        ).stdout.strip()
        if email:
            return email
    except (OSError, subprocess.SubprocessError):
        pass
    return DEFAULT_AUTHOR


def lifecycle_and_level(classifier: str) -> Tuple[str, str]:
    """CERT-In lifecycle class and SBOM level for what was scanned.

    A built container image is "analyzed" (post-build) and complete. A source tree resolved from
    manifests and lockfiles is "source" with transitive dependencies.
    """
    return ("analyzed", "complete") if classifier == "container" else ("source", "transitive")


def finalize_sbom_file(path: str, author: Optional[str], classifier: str) -> Dict[str, Any]:
    """Add the CERT-In fields to the SBOM at ``path`` in place and return the conformance report."""
    with open(path, "r", encoding="utf-8") as handle:
        doc = json.load(handle)
    lifecycle, level = lifecycle_and_level(classifier)
    if doc.get("bomFormat") == "CycloneDX":
        report = augment_cyclonedx(doc, author=author, lifecycle=lifecycle, level=level)
    elif "spdxVersion" in doc:
        report = augment_spdx(doc, author=author, lifecycle=lifecycle, level=level)
    else:
        raise ValueError("The SBOM is neither CycloneDX nor SPDX JSON")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2)
    return report


def check_file(path: str) -> Dict[str, Any]:
    """Conformance report for an existing SBOM file (CycloneDX/SPDX JSON or SPDX tag-value)."""
    with open(path, "r", encoding="utf-8") as handle:
        return validate_document(handle.read())


# Top-level fields only the AccuKnox platform reads. Neither the CycloneDX nor the SPDX schema
# allows them, so a strict validator rejects a file that carries them.
PLATFORM_ONLY_FIELDS = (
    "project_name", "project_classifier", "vm", "clusterInfo", "cluster_info", "ProjectName", "ProjectClassifier",
)


def copy_output(result_file: str, destination: Optional[str]) -> None:
    """Write the portable SBOM: the same document without the platform-only top-level fields.

    The file that is uploaded keeps them, because the platform reads the project from them.
    """
    if not destination:
        return
    with open(result_file, "r", encoding="utf-8") as handle:
        doc = json.load(handle)
    for key in PLATFORM_ONLY_FIELDS:
        doc.pop(key, None)
    with open(destination, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2)
    Logger.get_logger().info(f"SBOM written to {destination}")


def print_report(report: Dict[str, Any], strict: bool = False) -> None:
    """Human summary: the verdict, why it is not conformant, and what the verdict means."""
    log = Logger.get_logger()
    color = _STATUS_COLOR.get(report["status"], Fore.WHITE)
    Logger.log_with_color(
        "INFO",
        f"CERT-In SBOM data fields: {report['status_label']} "
        f"({report['components']} components, {report['populated_pct']}% of fields populated, "
        f"{report['declared_unknown_pct']}% declared unknown)",
        color,
    )
    for item in report["document"] + report["fields"]:
        if item["status"] == "fail":
            where = "document" if item["scope"] == "document" else f"{item['missing']} of {item['total']} components"
            log.warning(f"  missing {item['label']} (clause {item['clause']}): {where}")
    for item in report["checks"]:
        if item["status"] == "fail":
            log.warning(f"  {item['detail']}")
    log.info(f"  {report['pass_rule_note']}")


def is_conformant(report: Dict[str, Any]) -> bool:
    return report["status"] == CONFORMANT
