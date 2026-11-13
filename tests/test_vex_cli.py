"""VEX (OpenVEX / CycloneDX VEX / CSAF) applied to a CycloneDX SBOM, and the SBOM revision / supplier flags."""
import copy
import json
import os

import pytest

from aspm_cli.utils.certin_sbom import finalize_sbom_file
from aspm_cli.utils.sbom import append_vex_flags
from aspm_cli.utils.vex import VexError, apply_vex, load_vex, parse_vex, purl_key
from tests.test_certin_cli import CDX

OPENVEX = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "statements": [
        {
            "vulnerability": {"name": "CVE-2021-23337"},
            "products": [{"@id": "pkg:npm/lodash@4.17.20"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "impact_statement": "the vulnerable template function is never called",
        },
        {"vulnerability": {"name": "CVE-2099-1"}, "products": [{"@id": "pkg:npm/not-in-this-sbom@1"}], "status": "fixed"},
        {"vulnerability": {"name": "CVE-2099-2"}, "products": [{"@id": "pkg:npm/lodash"}], "status": "under_investigation"},
    ],
}


def _doc():
    doc = copy.deepcopy(CDX)
    doc["vulnerabilities"] = [
        {"id": "CVE-2021-23337", "ratings": [{"severity": "high", "score": 7.2}], "affects": [{"ref": "pkg:npm/lodash@4.17.20"}]}
    ]
    return doc


def test_openvex_statements_become_cyclonedx_analysis():
    statements = parse_vex(OPENVEX)
    assert [s["analysis"]["state"] for s in statements] == ["not_affected", "resolved", "in_triage"]
    assert statements[0]["analysis"]["justification"] == "code_not_reachable"
    assert statements[0]["analysis"]["detail"].startswith("the vulnerable template")


def test_apply_vex_annotates_the_listed_cve_adds_the_unlisted_one_and_drops_foreign_products():
    doc = _doc()
    result = apply_vex(doc, parse_vex(OPENVEX))
    assert result == {"applied": 2, "skipped": 1}  # the product that is not in this SBOM is dropped
    by_id = {v["id"]: v for v in doc["vulnerabilities"]}
    assert by_id["CVE-2021-23337"]["analysis"]["state"] == "not_affected"
    assert by_id["CVE-2021-23337"]["ratings"][0]["severity"] == "high"  # the scanner's own data is kept
    # A statement without a version covers every version of the package.
    assert by_id["CVE-2099-2"]["affects"] == [{"ref": "pkg:npm/lodash@4.17.20"}]
    assert "CVE-2099-1" not in by_id


def test_cyclonedx_vex_and_csaf_are_read():
    cdx_vex = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [
            {"id": "CVE-1", "analysis": {"state": "false_positive", "detail": "scanner noise"}, "affects": [{"ref": "pkg:npm/lodash@4.17.20"}]}
        ],
    }
    assert parse_vex(cdx_vex)[0]["analysis"] == {"state": "false_positive", "detail": "scanner noise"}

    csaf = {
        "document": {"category": "csaf_vex"},
        "product_tree": {"branches": [{"product": {"product_id": "P1", "product_identification_helper": {"purl": "pkg:npm/lodash@4.17.20"}}}]},
        "vulnerabilities": [
            {"cve": "CVE-2", "product_status": {"known_not_affected": ["P1"]}, "flags": [{"label": "component_not_present", "product_ids": ["P1"]}]}
        ],
    }
    stmt = parse_vex(csaf)[0]
    assert stmt["products"] == ["pkg:npm/lodash@4.17.20"]
    assert stmt["analysis"] == {"state": "not_affected", "justification": "code_not_present"}


def test_a_file_that_is_not_vex_is_refused(tmp_path):
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(VexError):
        load_vex(str(path))
    with pytest.raises(VexError):
        load_vex(str(tmp_path / "missing.json"))


def test_purl_key_ignores_qualifiers_and_reads_scoped_names():
    assert purl_key("pkg:npm/lodash@4.17.20?x=1#sub") == ("pkg:npm/lodash", "4.17.20")
    assert purl_key("pkg:npm/%40babel/core@7") == ("pkg:npm/@babel/core", "7")
    assert purl_key("pkg:npm/@babel/core") == ("pkg:npm/@babel/core", None)


def test_finalize_records_vex_and_the_revision_in_the_file(tmp_path):
    vex = tmp_path / "vex.json"
    vex.write_text(json.dumps(OPENVEX))
    path = tmp_path / "results.json"
    path.write_text(json.dumps(_doc()))
    finalize_sbom_file(str(path), "ci@acme.example", "container", bom_version=4, vex_files=[str(vex)])
    out = json.loads(path.read_text())
    assert out["version"] == 4
    assert next(v for v in out["vulnerabilities"] if v["id"] == "CVE-2021-23337")["analysis"]["state"] == "not_affected"
    # a bad VEX file is skipped, not fatal
    finalize_sbom_file(str(path), "ci@acme.example", "container", vex_files=[str(tmp_path / "nope.json")])


def test_vex_is_passed_to_trivy_by_absolute_path_and_under_workdir_in_container_mode(tmp_path, monkeypatch):
    inside = tmp_path / "vex.json"
    inside.write_text("{}")
    monkeypatch.chdir(tmp_path)
    assert append_vex_flags(["fs", "."], [str(inside)]) == ["fs", ".", "--vex", os.path.realpath(inside)]
    assert append_vex_flags(["fs", "."], [str(inside)], container_mode=True) == ["fs", ".", "--vex", "/workdir/vex.json"]
    # outside the mounted working directory Trivy cannot see it: left out of the command
    assert append_vex_flags(["fs", "."], ["/etc/hosts"], container_mode=True) == ["fs", "."]
    assert append_vex_flags(["fs", "."], None) == ["fs", "."]
