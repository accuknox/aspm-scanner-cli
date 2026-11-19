"""CERT-In SBOM support in the CLI: stamping, the check flag, format choice, vendored-code parity."""
import argparse
import hashlib
import json
import os
from pathlib import Path

import pytest

from aspm_cli.scan.container import ContainerScanner
from aspm_cli.utils import certin_sbom
from aspm_cli.utils.certin_sbom import (
    check_file,
    finalize_sbom_file,
    lifecycle_and_level,
    resolve_sbom_author,
)
from aspm_cli.utils.sbom import enrich_sbom_payload, is_sbom_payload_empty
from aspm_cli.utils.scan_runner import _finalize_certin

CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "metadata": {
        "tools": {"components": [{"type": "application", "name": "accuknox-container-scanner"}]},
        "component": {"type": "application", "bom-ref": "root", "name": "shop", "version": "1.0"},
    },
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:npm/lodash@4.17.20",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "licenses": [{"license": {"id": "MIT"}}],
        }
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["pkg:npm/lodash@4.17.20"]}],
    "vulnerabilities": [],
}

SPDX = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "shop",
    "documentNamespace": "https://example.test/shop-1",
    "creationInfo": {"created": "2026-11-05T10:00:00Z", "creators": ["Tool: syft-1.42"]},
    "packages": [
        {"SPDXID": "SPDXRef-root", "name": "shop", "versionInfo": "1.0", "downloadLocation": "NOASSERTION",
         "primaryPackagePurpose": "APPLICATION"},
        {"SPDXID": "SPDXRef-lodash", "name": "lodash", "versionInfo": "4.17.20", "downloadLocation": "NOASSERTION",
         "licenseDeclared": "MIT",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                           "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-root"},
        {"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-lodash"},
    ],
}


def _write(tmp_path, doc, name="results.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc))
    return str(path)


def test_scanner_cyclonedx_is_not_conformant_until_finalized(tmp_path):
    path = _write(tmp_path, CDX)
    assert check_file(path)["status"] == "non_conformant"
    report = finalize_sbom_file(path, "ci@acme.example", "container")
    assert report["status"] == "conformant"
    stamped = json.loads(Path(path).read_text())
    assert stamped["metadata"]["authors"] == [{"name": "ci@acme.example"}]
    assert stamped["metadata"]["lifecycles"] == [{"phase": "post-build"}]
    assert check_file(path)["attestation"]["matches"] is True


def test_scanner_spdx_is_finalized(tmp_path):
    path = _write(tmp_path, SPDX)
    assert check_file(path)["status"] == "non_conformant"
    assert finalize_sbom_file(path, "ci@acme.example", "application")["status"] == "conformant"
    assert "Person: ci@acme.example" in json.loads(Path(path).read_text())["creationInfo"]["creators"]


def test_unknown_document_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        finalize_sbom_file(_write(tmp_path, {"hello": "world"}), "a", "container")


def test_lifecycle_and_level():
    assert lifecycle_and_level("container") == ("analyzed", "complete")
    assert lifecycle_and_level("application") == ("source", "transitive")


def test_author_precedence(monkeypatch):
    for name in ("ACCUKNOX_SBOM_AUTHOR", "GITLAB_USER_EMAIL", "BUILD_REQUESTEDFOREMAIL", "GITHUB_ACTOR",
                 "GITLAB_USER_LOGIN", "BUILD_REQUESTEDFOR", "CIRCLE_USERNAME", "BUILD_USER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GITHUB_ACTOR", "octocat")
    assert resolve_sbom_author() == "octocat"
    monkeypatch.setenv("ACCUKNOX_SBOM_AUTHOR", "release-bot")
    assert resolve_sbom_author() == "release-bot"
    assert resolve_sbom_author("explicit") == "explicit"


def test_author_falls_back_to_the_tool_when_nothing_identifies_anyone(monkeypatch):
    for name in ("ACCUKNOX_SBOM_AUTHOR", "GITLAB_USER_EMAIL", "BUILD_REQUESTEDFOREMAIL", "GITHUB_ACTOR",
                 "GITLAB_USER_LOGIN", "BUILD_REQUESTEDFOR", "CIRCLE_USERNAME", "BUILD_USER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(certin_sbom.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": ""})())
    assert resolve_sbom_author() == certin_sbom.DEFAULT_AUTHOR


def test_sbom_format_selects_the_trivy_output_format():
    args = ContainerScanner("image nginx:latest", generate_sbom=True, sbom_format="spdx")._build_container_scan_args()[1]
    assert args[args.index("-f") + 1] == "spdx-json"
    default = ContainerScanner("image nginx:latest", generate_sbom=True)._build_container_scan_args()[1]
    assert default[default.index("-f") + 1] == "cyclonedx"


def test_spdx_project_fields_are_pascal_case():
    data = json.loads(json.dumps(SPDX))
    enrich_sbom_payload(data, "image nginx", "payments", "container")
    assert data["ProjectName"] == "payments" and data["ProjectClassifier"] == "container"
    assert "project_name" not in data


def test_empty_spdx_is_detected():
    assert is_sbom_payload_empty({"spdxVersion": "SPDX-2.3", "packages": []})
    assert not is_sbom_payload_empty(SPDX)


def _args(**kw):
    values = dict(command="image nginx:latest", sbom_author="ci@acme.example", cert_in_check=False, sbom_output=None)
    values.update(kw)
    return argparse.Namespace(**values)


def test_cert_in_check_fails_the_run_only_when_not_conformant(tmp_path):
    failing = json.loads(json.dumps(CDX))
    failing["components"][0].pop("licenses")  # still conformant: declared unknown
    path = _write(tmp_path, failing)
    assert _finalize_certin(_args(cert_in_check=True), path) is False

    broken = _write(tmp_path, {"not": "an sbom"}, "bad.json")
    assert _finalize_certin(_args(cert_in_check=True), broken) is True  # cannot verify -> fail
    assert _finalize_certin(_args(cert_in_check=False), broken) is False  # not asked -> never blocks


def test_sbom_output_copy(tmp_path):
    path = _write(tmp_path, CDX)
    out = tmp_path / "out" / "sbom.cdx.json"
    out.parent.mkdir()
    assert _finalize_certin(_args(sbom_author="a", sbom_output=str(out)), path) is False
    portable = json.loads(out.read_text())
    assert portable["metadata"]["authors"] == [{"name": "a"}]
    # Platform-only top-level fields stay in the uploaded file but not in the portable copy.
    uploaded = json.loads(Path(path).read_text())
    assert "project_classifier" in uploaded or "project_classifier" not in portable


def test_portable_copy_drops_platform_only_fields(tmp_path):
    doc = json.loads(json.dumps(CDX))
    doc.update({"project_name": "payments", "project_classifier": "container", "clusterInfo": {"a": 1}})
    src = _write(tmp_path, doc)
    out = tmp_path / "portable.json"
    certin_sbom.copy_output(src, str(out))
    portable = json.loads(out.read_text())
    assert not set(certin_sbom.PLATFORM_ONLY_FIELDS) & set(portable)
    assert json.loads(Path(src).read_text())["project_name"] == "payments"


def test_vendored_certin_matches_the_platform_copy():
    """The CLI's aspm_cli/certin is a copy of cspm-backend xbom/certin: they must not drift."""
    here = Path(__file__).resolve().parents[1]
    source = Path(os.environ.get("CSPM_BACKEND_PATH", here.parent / "cspm-backend")) / "xbom" / "certin"
    if not source.is_dir():
        pytest.skip("platform source not available; set CSPM_BACKEND_PATH")
    vendored = here / "aspm_cli" / "certin"
    names = sorted(p.name for p in vendored.iterdir() if p.suffix in (".py", ".json") and p.name != "__init__.py")
    assert names, "vendored package is empty"
    for name in names:
        assert hashlib.sha256((vendored / name).read_bytes()).hexdigest() == hashlib.sha256(
            (source / name).read_bytes()
        ).hexdigest(), f"{name} differs from the platform copy; re-copy it"


def _run_check(tmp_path, doc, *extra):
    from aspm_cli.commands.cert_in_command import CertInCheckCommand

    parser = argparse.ArgumentParser()
    command = CertInCheckCommand()
    command.configure_parser(parser)
    args = parser.parse_args([_write(tmp_path, doc, "in.json"), *extra])
    with pytest.raises(SystemExit) as exit_info:
        args.func(args)
    return exit_info.value.code


def test_cert_in_check_command_exit_codes(tmp_path, capsys):
    assert _run_check(tmp_path, CDX) == 1  # a raw scanner file is not conformant
    final = tmp_path / "final.json"
    final.write_text(json.dumps(CDX))
    finalize_sbom_file(str(final), "ci@acme.example", "container")
    assert _run_check(tmp_path, json.loads(final.read_text())) == 0
    assert _run_check(tmp_path, {"not": "an sbom"}) == 2


def test_cert_in_check_command_json_output(tmp_path, capsys):
    final = tmp_path / "final.json"
    final.write_text(json.dumps(CDX))
    finalize_sbom_file(str(final), "ci@acme.example", "container")
    _run_check(tmp_path, json.loads(final.read_text()), "--json")
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "conformant" and report["attestation"]["matches"] is True


def test_spdx_creators_do_not_name_the_upstream_scanner(tmp_path):
    data = json.loads(json.dumps(SPDX))
    data["creationInfo"]["creators"] = ["Organization: aquasecurity", "Tool: trivy-0.69.3"]
    enrich_sbom_payload(data, "image nginx", "payments", "container")
    assert data["creationInfo"]["creators"] == ["Organization: AccuKnox", "Tool: accuknox-container-scanner"]


def test_a_scanner_organization_is_not_taken_as_the_author(tmp_path):
    data = json.loads(json.dumps(SPDX))
    data["creationInfo"]["creators"] = ["Organization: AccuKnox", "Tool: accuknox-container-scanner"]
    path = _write(tmp_path, data)
    finalize_sbom_file(path, "ci@acme.example", "application")
    creators = json.loads(Path(path).read_text())["creationInfo"]["creators"]
    assert "Person: ci@acme.example" in creators
