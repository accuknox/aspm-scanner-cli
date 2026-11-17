import json
import os
import tempfile
import unittest
from unittest.mock import patch

from aspm_cli.inference.base import InferredDep
from aspm_cli.scan.container import ContainerScanner
from aspm_cli.utils.sbom import sanitize_scanner_branding_from_bom
from aspm_cli.utils.sbom_merge import (
    append_components,
    build_delta_bom,
    merge_components,
    merge_vulnerabilities,
    purl_key,
)


def trivy_doc():
    return {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"bom-ref": "root", "name": "repo", "type": "application"}},
        "components": [
            {"bom-ref": "t-zlib", "type": "library", "name": "zlib", "version": "1.2.11",
             "purl": "pkg:conan/zlib@1.2.11"},
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["t-zlib"]}],
        "vulnerabilities": [
            {"id": "CVE-1", "affects": [{"ref": "t-zlib", "versions": [{"version": "1.2.11", "status": "affected"}]}]}
        ],
    }


def syft_doc():
    return {
        "metadata": {"component": {"bom-ref": "s-root", "name": "dir", "type": "file"}},
        "components": [
            {"bom-ref": "pkg:conan/zlib@1.2.11?package-id=abc", "type": "library", "name": "zlib", "version": "1.2.11",
             "purl": "pkg:conan/zlib@1.2.11?package-id=abc", "licenses": [{"license": {"id": "Zlib"}}],
             "properties": [{"name": "syft:package:foundBy", "value": "conan-cataloger"}]},
            {"bom-ref": "pkg:conan/libpng@1.6.34", "type": "library", "name": "libpng", "version": "1.6.34",
             "purl": "pkg:conan/libpng@1.6.34"},
            {"bom-ref": "file-1", "type": "file", "name": "/src/conanfile.txt"},
        ],
        "dependencies": [
            {"ref": "s-root", "dependsOn": ["pkg:conan/zlib@1.2.11?package-id=abc", "pkg:conan/libpng@1.6.34"]},
            {"ref": "pkg:conan/libpng@1.6.34", "dependsOn": ["pkg:conan/zlib@1.2.11?package-id=abc"]},
        ],
    }


class TestComponentMerge(unittest.TestCase):
    def test_purl_key_ignores_qualifiers_and_case(self):
        self.assertEqual(purl_key("pkg:Conan/Zlib@1.2.11?package-id=abc#x"), "pkg:conan/zlib@1.2.11")
        self.assertIsNone(purl_key("not-a-purl"))

    def test_matched_component_keeps_trivy_ref_and_gains_license(self):
        base = trivy_doc()
        ref_map, stats = merge_components(base, syft_doc(), "inventory")
        zlib = next(c for c in base["components"] if c["name"] == "zlib")
        self.assertEqual(zlib["bom-ref"], "t-zlib")
        self.assertEqual(zlib["licenses"], [{"license": {"id": "Zlib"}}])
        self.assertEqual(ref_map["pkg:conan/zlib@1.2.11?package-id=abc"], "t-zlib")
        self.assertEqual(stats, {"matched": 1, "added": 1, "skipped": 1})

    def test_existing_licenses_are_not_overwritten(self):
        base = trivy_doc()
        base["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
        merge_components(base, syft_doc(), "inventory")
        self.assertEqual(base["components"][0]["licenses"], [{"license": {"id": "MIT"}}])

    def test_syft_only_component_appended_file_components_skipped(self):
        base = trivy_doc()
        merge_components(base, syft_doc(), "inventory")
        names = [c["name"] for c in base["components"]]
        self.assertEqual(sorted(names), ["libpng", "zlib"])
        libpng = next(c for c in base["components"] if c["name"] == "libpng")
        self.assertIn({"name": "accuknox:found-by", "value": "inventory"}, libpng["properties"])

    def test_dependencies_are_remapped_and_unioned(self):
        base = trivy_doc()
        merge_components(base, syft_doc(), "inventory")
        edges = {d["ref"]: d["dependsOn"] for d in base["dependencies"]}
        self.assertEqual(edges["root"], ["pkg:conan/libpng@1.6.34", "t-zlib"])
        self.assertEqual(edges["pkg:conan/libpng@1.6.34"], ["t-zlib"])
        known = {c["bom-ref"] for c in base["components"]} | {"root"}
        for ref, deps in edges.items():
            self.assertIn(ref, known)
            self.assertTrue(set(deps) <= known)

    def test_ref_collision_is_made_unique(self):
        base = trivy_doc()
        extra = {"components": [{"bom-ref": "t-zlib", "type": "library", "name": "other", "version": "1", "purl": "pkg:conan/other@1"}]}
        ref_map, _ = merge_components(base, extra, "inventory")
        self.assertEqual(ref_map["t-zlib"], "t-zlib~2")
        self.assertEqual(len({c["bom-ref"] for c in base["components"]}), 2)

    def test_versionless_inferred_components_are_appended_with_origin(self):
        base = trivy_doc()
        dep = InferredDep("boost", None, "pkg:conan/boost", "conan", "C", "include-only")
        stats = append_components(base, [dep.to_component()], "source-inference")
        self.assertEqual(stats["added"], 1)
        boost = next(c for c in base["components"] if c["name"] == "boost")
        self.assertNotIn("version", boost)
        self.assertIn({"name": "accuknox:found-by", "value": "source-inference"}, boost["properties"])


class TestVulnerabilityMergeAndDelta(unittest.TestCase):
    def test_same_id_same_component_kept_once_new_component_added(self):
        base = trivy_doc()
        extra = {"vulnerabilities": [
            {"id": "CVE-1", "affects": [{"ref": "t-zlib"}, {"ref": "x-new", "versions": [{"version": "1", "status": "affected"}]}]},
            {"id": "CVE-2", "affects": [{"ref": "x-new"}]},
        ]}
        added = merge_vulnerabilities(base, extra)
        self.assertEqual(added, 2)
        by_id = {v["id"]: v for v in base["vulnerabilities"]}
        self.assertEqual([a["ref"] for a in by_id["CVE-1"]["affects"]], ["t-zlib", "x-new"])
        self.assertEqual(by_id["CVE-1"]["affects"][1]["versions"][0]["version"], "1")
        self.assertEqual(len(base["vulnerabilities"]), 2)

    def test_delta_contains_only_new_versioned_registry_components(self):
        base = trivy_doc()
        original = {c["bom-ref"] for c in base["components"]}
        merge_components(base, syft_doc(), "inventory")
        append_components(base, [
            InferredDep("openssl", "1.1.1k", "pkg:conan/openssl@1.1.1k", "conan", "B", "vendored").to_component(),
            InferredDep("boost", None, "pkg:conan/boost", "conan", "C", "include-only").to_component(),
            InferredDep("core", "a" * 40, "pkg:github/acme/core@" + "a" * 40, "github", "A", "git").to_component(),
            InferredDep("codec", "2.4.1", "pkg:generic/codec@2.4.1", "generic", "B", "vendored").to_component(),
        ], "source-inference")
        delta = build_delta_bom(base, original)
        self.assertEqual(sorted(c["name"] for c in delta["components"]), ["libpng", "openssl"])

    def test_delta_none_when_nothing_new(self):
        base = trivy_doc()
        self.assertIsNone(build_delta_bom(base, {c["bom-ref"] for c in base["components"]}))


class TestBranding(unittest.TestCase):
    def test_syft_properties_are_renamed(self):
        base = trivy_doc()
        merge_components(base, syft_doc(), "inventory")
        sanitize_scanner_branding_from_bom(base)
        text = json.dumps(base).lower()
        self.assertNotIn("syft", text)
        self.assertIn("accuknox:scanner:package:foundby", text)


class TestContainerMergeOrchestration(unittest.TestCase):
    def _scanner(self, **kwargs):
        scanner = ContainerScanner("filesystem .", generate_sbom=True, **kwargs)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        scanner.result_file = os.path.join(self.tmp.name, "results.json")
        with open(scanner.result_file, "w") as handle:
            json.dump(trivy_doc(), handle)
        return scanner

    def test_default_merges_syft_and_looks_up_only_the_delta(self):
        scanner = self._scanner(infer_deps=False)

        def run_syft_step():
            scanner._syft_doc = syft_doc()
            return 0

        findings = {"vulnerabilities": [{"id": "CVE-9", "affects": [{"ref": "pkg:conan/libpng@1.6.34"}]}]}
        with patch.object(scanner, "_enrich_licenses_from_syft", side_effect=run_syft_step), \
             patch.object(scanner, "_lookup_delta_findings", return_value=findings) as lookup:
            self.assertEqual(scanner._merge_inventory(), 0)
        delta = lookup.call_args[0][0]
        self.assertEqual([c["name"] for c in delta["components"]], ["libpng"])
        merged = json.load(open(scanner.result_file))
        self.assertEqual({c["name"] for c in merged["components"]}, {"zlib", "libpng"})
        self.assertEqual({v["id"] for v in merged["vulnerabilities"]}, {"CVE-1", "CVE-9"})

    def test_opt_outs_leave_trivy_document_untouched(self):
        scanner = self._scanner(syft_merge=False, infer_deps=False)
        before = open(scanner.result_file).read()
        with patch.object(scanner, "_run_syft") as syft:
            self.assertEqual(scanner._merge_inventory(), 0)
        syft.assert_not_called()
        self.assertEqual(open(scanner.result_file).read(), before)

    def test_missing_syft_is_a_warning_by_default_and_an_error_when_explicit(self):
        scanner = self._scanner(infer_deps=False)
        with patch.object(scanner, "_run_syft", side_effect=FileNotFoundError("missing")):
            self.assertEqual(scanner._merge_inventory(), 0)
        explicit = self._scanner(infer_deps=False, enrich_licenses=True)
        with patch.object(explicit, "_run_syft", side_effect=FileNotFoundError("missing")):
            self.assertEqual(explicit._merge_inventory(), 1)

    def test_image_merges_syft_but_never_infers(self):
        image = ContainerScanner("image nginx:latest", generate_sbom=True)
        image.result_file = self._write(trivy_doc())
        with patch.object(image, "_enrich_licenses_from_syft", side_effect=lambda: setattr(image, "_syft_doc", syft_doc()) or 0), \
             patch("aspm_cli.scan.container.infer_dependencies") as infer, \
             patch.object(image, "_lookup_delta_findings", return_value=None):
            self.assertEqual(image._merge_inventory(), 0)
        infer.assert_not_called()
        self.assertEqual({c["name"] for c in json.load(open(image.result_file))["components"]}, {"zlib", "libpng"})

    def test_spdx_is_merged_without_an_advisory_pass(self):
        spdx = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"SPDXID": "SPDXRef-Package-zlib", "name": "zlib", "versionInfo": "1.2.11",
                          "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:conan/zlib@1.2.11"}]}],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                               "relatedSpdxElement": "SPDXRef-Root"}],
        }
        scanner = ContainerScanner("filesystem .", generate_sbom=True, sbom_format="spdx", infer_deps=False)
        scanner.result_file = self._write(spdx)
        with patch.object(scanner, "_enrich_licenses_from_syft", side_effect=lambda: setattr(scanner, "_syft_doc", syft_doc()) or 0), \
             patch.object(scanner, "_lookup_delta_findings") as lookup:
            self.assertEqual(scanner._merge_inventory(), 0)
        lookup.assert_not_called()
        merged = json.load(open(scanner.result_file))
        self.assertEqual([p["name"] for p in merged["packages"]], ["zlib", "libpng"])  # zlib matched, not duplicated
        added = merged["packages"][1]
        self.assertEqual(added["versionInfo"], "1.6.34")
        self.assertIn({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:conan/libpng@1.6.34"}, added["externalRefs"])
        self.assertIn("found-by=inventory", added["comment"])
        self.assertIn({"spdxElementId": "SPDXRef-Root", "relationshipType": "DEPENDS_ON",
                       "relatedSpdxElement": added["SPDXID"]}, merged["relationships"])

    def test_spdx_merge_adds_inferred_packages_with_flags(self):
        from aspm_cli.utils.sbom_merge import merge_into_spdx
        spdx = {"spdxVersion": "SPDX-2.3", "packages": [], "relationships": []}
        dep = InferredDep("boost", None, "pkg:conan/boost", "conan", "C", "include-only", ["a.cpp:1"])
        stats = merge_into_spdx(spdx, None, [dep.to_component()])
        self.assertEqual(stats["added"], 1)
        pkg = spdx["packages"][0]
        self.assertNotIn("versionInfo", pkg)
        self.assertIn("confidence=C", pkg["comment"])
        self.assertIn("evidence=a.cpp:1", pkg["comment"])

    def test_cache_volume_is_shared_by_container_runs_and_removed(self):
        scanner = ContainerScanner("filesystem .", container_mode=True, generate_sbom=True)
        calls = []
        with patch.object(scanner, "_run", side_effect=lambda: calls.append(scanner._cache_volume) or (0, None)), \
             patch("aspm_cli.scan.container.subprocess.run") as run:
            scanner.run()
        self.assertTrue(calls[0].startswith("accuknox-trivy-cache-"))
        run.assert_called_once()
        self.assertEqual(run.call_args[0][0], ["docker", "volume", "rm", "-f", calls[0]])
        self.assertIsNone(scanner._cache_volume)
        cmd = ["docker", "run", "--rm", "-v", "x:/workdir", "img"]
        scanner._cache_volume = "vol1"
        self.assertEqual(scanner._with_cache(cmd)[:6], ["docker", "run", "--rm", "-v", "vol1:/root/.cache/trivy", "-v"])

    def test_no_cache_volume_for_native_runs_or_opt_outs(self):
        seen = []
        for kwargs in ({"container_mode": False}, {"container_mode": True, "syft_merge": False, "infer_deps": False}):
            scanner = ContainerScanner("filesystem .", generate_sbom=True, **kwargs)
            with patch.object(scanner, "_run", side_effect=lambda s=scanner: seen.append(s._cache_volume) or (0, None)):
                scanner.run()
        self.assertEqual(seen, [None, None])

    def _write(self, doc):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "results.json")
        with open(path, "w") as handle:
            json.dump(doc, handle)
        return path

    def test_failed_delta_lookup_keeps_components_without_findings(self):
        scanner = self._scanner(infer_deps=False)
        with patch.object(scanner, "_enrich_licenses_from_syft", side_effect=lambda: setattr(scanner, "_syft_doc", syft_doc()) or 0), \
             patch.object(scanner, "_lookup_delta_findings", return_value=None):
            self.assertEqual(scanner._merge_inventory(), 0)
        merged = json.load(open(scanner.result_file))
        self.assertEqual(len(merged["components"]), 2)
        self.assertEqual([v["id"] for v in merged["vulnerabilities"]], ["CVE-1"])


if __name__ == "__main__":
    unittest.main()


class TestUnknownVersions(unittest.TestCase):
    def test_unknown_version_is_not_a_lookup_candidate(self):
        from aspm_cli.utils.sbom_merge import is_lookup_candidate
        self.assertFalse(is_lookup_candidate({"name": "x", "version": "UNKNOWN", "purl": "pkg:maven/x/x"}))
        self.assertTrue(is_lookup_candidate({"name": "x", "version": "1.0", "purl": "pkg:maven/x/x@1.0"}))


class TestLinkAddedComponents(unittest.TestCase):
    def test_added_components_get_entries_and_hang_off_the_root_when_unreferenced(self):
        from aspm_cli.utils.sbom_merge import link_added_components
        base = trivy_doc()
        original = {c["bom-ref"] for c in base["components"]}
        merge_components(base, syft_doc(), "inventory")
        append_components(base, [InferredDep("boost", None, "pkg:conan/boost", "conan", "C", "include-only").to_component()], "source-inference")
        link_added_components(base, original)
        edges = {d["ref"]: d["dependsOn"] for d in base["dependencies"]}
        for comp in base["components"]:
            if comp["bom-ref"] not in original:  # Trivy's own entries are Trivy's to provide
                self.assertIn(comp["bom-ref"], edges, comp["name"])  # clause 4.2.7: every added component has one
        self.assertIn("pkg:conan/boost", edges["root"])
        self.assertEqual(edges["pkg:conan/boost"], [])
        self.assertEqual(edges["root"].count("t-zlib"), 1)  # Trivy's own edge is not duplicated
        # libpng is depended on by nothing in Syft's graph except the root edge already merged
        self.assertEqual(edges["root"].count("pkg:conan/libpng@1.6.34"), 1)

    def test_idempotent(self):
        from aspm_cli.utils.sbom_merge import link_added_components
        base = trivy_doc()
        original = {c["bom-ref"] for c in base["components"]}
        append_components(base, [InferredDep("boost", None, "pkg:conan/boost", "conan", "C", "include-only").to_component()], "x")
        link_added_components(base, original)
        first = json.dumps(base["dependencies"], sort_keys=True)
        link_added_components(base, original)
        self.assertEqual(first, json.dumps(base["dependencies"], sort_keys=True))
