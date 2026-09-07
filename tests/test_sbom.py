import os
import unittest
from unittest.mock import patch

from aspm_cli.scan.container import ContainerScanner
from aspm_cli.tool.download import SYFT_VERSION, syft_release_asset
from aspm_cli.utils.config import ConfigValidator
from aspm_cli.utils.sbom import (
    append_sbom_scanner_flags,
    derive_sbom_classifier,
    enrich_sbom_payload,
    is_sbom_payload_empty,
    normalize_filesystem_args_for_docker,
    normalize_sbom_args_for_docker,
    parse_trivy_subcommand,
    resolve_project_name,
    sanitize_scanner_branding_from_bom,
    validate_sbom_command,
)
from aspm_cli.utils.sbom_license_merge import (
    merge_syft_licenses_into_trivy,
    normalize_license_id,
    should_enrich_filesystem_licenses,
    syft_scan_source,
)


class TestSbomHelpers(unittest.TestCase):
    def test_parse_trivy_subcommand_skips_flags(self):
        self.assertEqual(
            parse_trivy_subcommand("--format json image nginx:latest"),
            "image",
        )

    def test_derive_sbom_classifier_filesystem(self):
        self.assertEqual(derive_sbom_classifier("filesystem ."), "application")
        self.assertEqual(derive_sbom_classifier("fs ./src"), "application")

    def test_derive_sbom_classifier_image(self):
        self.assertEqual(derive_sbom_classifier("image nginx:latest"), "container")
        self.assertEqual(derive_sbom_classifier("rootfs /tmp/rootfs"), "container")

    def test_derive_sbom_classifier_unknown_defaults_container(self):
        self.assertEqual(derive_sbom_classifier("unknown foo"), "container")

    def test_validate_sbom_command_rejects_invalid(self):
        with self.assertRaises(ValueError):
            validate_sbom_command("config .")

    def test_normalize_filesystem_relative_path(self):
        args = normalize_filesystem_args_for_docker(["filesystem", "./src"])
        self.assertEqual(args, ["filesystem", "/workdir/src"])

    def test_normalize_filesystem_dot(self):
        args = normalize_filesystem_args_for_docker(["filesystem", "."])
        self.assertEqual(args, ["filesystem", "/workdir"])

    def test_normalize_filesystem_workdir_unchanged(self):
        args = normalize_filesystem_args_for_docker(["filesystem", "/workdir/backend"])
        self.assertEqual(args, ["filesystem", "/workdir/backend"])

    def test_normalize_sbom_args_image_unchanged(self):
        args = ["image", "nginx:latest", "-f", "cyclonedx"]
        self.assertEqual(
            normalize_sbom_args_for_docker("image nginx:latest", args),
            args,
        )

    def test_append_sbom_scanner_flags_adds_vuln_license(self):
        args = append_sbom_scanner_flags(["filesystem", ".", "-f", "cyclonedx"])
        self.assertIn("--scanners", args)
        self.assertIn("vuln,license", args)

    def test_append_sbom_scanner_flags_skips_when_present(self):
        original = ["fs", ".", "--scanners", "license"]
        self.assertEqual(append_sbom_scanner_flags(original), original)

    def test_is_sbom_payload_empty(self):
        self.assertTrue(is_sbom_payload_empty({}))
        self.assertTrue(is_sbom_payload_empty({"components": []}))
        self.assertFalse(is_sbom_payload_empty({"components": [{"name": "pkg"}]}))
        self.assertFalse(is_sbom_payload_empty({"metadata": {"component": {"name": "app"}}}))

    def test_enrich_sbom_payload(self):
        data = {
            "metadata": {
                "component": {"name": ".", "group": "aquasecurity"},
                "tools": {"components": [{"name": "trivy"}]},
            }
        }
        enrich_sbom_payload(data, "filesystem .", "my-app", "application")
        self.assertEqual(data["project_name"], "my-app")
        self.assertEqual(data["project_classifier"], "application")
        self.assertNotIn("group", data["metadata"]["component"])

    def test_sanitize_scanner_branding_from_bom(self):
        data = {
            "metadata": {
                "tools": {"components": [{"name": "trivy", "group": "aquasecurity"}]},
                "component": {
                    "manufacturer": {"name": "Aqua Security"},
                    "properties": [{"name": "aquasecurity:trivy:foo", "value": "bar"}],
                },
            },
            "components": [{"properties": [{"name": "aquasecurity:trivy:pkg", "value": "1"}]}],
        }
        sanitize_scanner_branding_from_bom(data)
        self.assertEqual(data["metadata"]["tools"]["components"][0]["name"], "accuknox-container-scanner")
        self.assertEqual(
            data["metadata"]["component"]["properties"][0]["name"],
            "accuknox:scanner:foo",
        )

    def test_resolve_project_name_priority(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_project_name("cli-name"), "cli-name")
        with patch.dict(
            os.environ,
            {"ACCUKNOX_PROJECT_NAME": "from-name", "ACCUKNOX_PROJECT": "from-legacy"},
            clear=True,
        ):
            self.assertEqual(resolve_project_name(None), "from-name")
        with patch.dict(os.environ, {"ACCUKNOX_PROJECT": "legacy-only"}, clear=True):
            self.assertEqual(resolve_project_name(None), "legacy-only")


class TestContainerScanValidation(unittest.TestCase):
    def _validator(self, skip_upload=False, project_name=None):
        return ConfigValidator(
            "container",
            softfail=False,
            skip_upload=skip_upload,
            accuknox_endpoint="https://example.com",
            accuknox_label="label",
            accuknox_token="token",
            accuknox_project_name=project_name,
        )

    def test_vuln_scan_no_project_name_required(self):
        v = self._validator(skip_upload=False, project_name=None)
        v.validate_container_scan("image nginx:latest", True, generate_sbom=False)

    def test_sbom_skip_upload_no_project_name(self):
        v = self._validator(skip_upload=True, project_name=None)
        v.validate_container_scan("filesystem .", True, generate_sbom=True)

    def test_sbom_upload_requires_project_name(self):
        v = self._validator(skip_upload=False, project_name=None)
        with self.assertRaises(ValueError) as ctx:
            v.validate_container_scan("filesystem .", True, generate_sbom=True)
        self.assertIn("project name", str(ctx.exception).lower())

    def test_sbom_upload_with_project_name(self):
        v = self._validator(skip_upload=False, project_name="my-app")
        v.validate_container_scan("filesystem .", True, generate_sbom=True)


class TestSbomLicenseMerge(unittest.TestCase):
    def test_normalize_aliases_and_hashes(self):
        self.assertEqual(normalize_license_id("Apache 2.0"), "Apache-2.0")
        self.assertEqual(normalize_license_id("Apache License 2.0"), "Apache-2.0")
        self.assertEqual(normalize_license_id("Apache 2"), "Apache-2.0")
        self.assertEqual(normalize_license_id("BSD"), "BSD-3-Clause")
        self.assertEqual(normalize_license_id("3-Clause BSD License"), "BSD-3-Clause")
        self.assertEqual(normalize_license_id("MIT"), "MIT")
        self.assertEqual(normalize_license_id("MIT OR Apache-2.0"), "MIT OR Apache-2.0")
        self.assertIsNone(normalize_license_id("UNKNOWN"))
        self.assertIsNone(normalize_license_id("sha256:abcd"))

    def test_hash_id_falls_back_to_alias_name(self):
        trivy = {
            "components": [
                {"name": "pkg", "version": "1", "purl": "pkg:generic/pkg@1"}
            ]
        }
        syft = {
            "components": [
                {
                    "name": "pkg",
                    "version": "1",
                    "purl": "pkg:generic/pkg@1",
                    "licenses": [
                        {"license": {"id": "sha256:deadbeef", "name": "Apache 2.0"}}
                    ],
                }
            ]
        }
        merge_syft_licenses_into_trivy(trivy, syft)
        self.assertEqual(
            trivy["components"][0]["licenses"],
            [{"license": {"id": "Apache-2.0"}}],
        )

    def test_fill_empty_trivy_licenses_via_purl(self):
        trivy = {
            "components": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                }
            ]
        }
        syft = {
            "components": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                    "licenses": [{"license": {"name": "Apache 2.0"}}],
                },
                {
                    "name": "orphan-file",
                    "licenses": [{"license": {"id": "MIT"}}],
                },
            ]
        }
        stats = merge_syft_licenses_into_trivy(trivy, syft)
        self.assertEqual(stats["enriched"], 1)
        self.assertEqual(
            trivy["components"][0]["licenses"],
            [{"license": {"id": "Apache-2.0"}}],
        )
        self.assertEqual(len(trivy["components"]), 1)

    def test_existing_trivy_license_not_overwritten(self):
        trivy = {
            "components": [
                {
                    "name": "foo",
                    "version": "1.0.0",
                    "purl": "pkg:npm/foo@1.0.0",
                    "licenses": [{"license": {"id": "MIT"}}],
                }
            ]
        }
        syft = {
            "components": [
                {
                    "name": "foo",
                    "version": "1.0.0",
                    "purl": "pkg:npm/foo@1.0.0",
                    "licenses": [{"license": {"id": "Apache-2.0"}}],
                }
            ]
        }
        stats = merge_syft_licenses_into_trivy(trivy, syft)
        self.assertEqual(stats["skipped_existing"], 1)
        self.assertEqual(stats["enriched"], 0)
        self.assertEqual(
            trivy["components"][0]["licenses"],
            [{"license": {"id": "MIT"}}],
        )

    def test_match_by_name_version_when_purl_missing(self):
        trivy = {"components": [{"name": "bar", "version": "3.2.1"}]}
        syft = {
            "components": [
                {
                    "name": "bar",
                    "version": "3.2.1",
                    "licenses": [{"license": {"id": "ISC"}}],
                }
            ]
        }
        merge_syft_licenses_into_trivy(trivy, syft)
        self.assertEqual(
            trivy["components"][0]["licenses"],
            [{"license": {"id": "ISC"}}],
        )

    def test_hash_licenses_ignored(self):
        trivy = {
            "components": [
                {"name": "hashed", "version": "1", "purl": "pkg:generic/hashed@1"}
            ]
        }
        syft = {
            "components": [
                {
                    "name": "hashed",
                    "version": "1",
                    "purl": "pkg:generic/hashed@1",
                    "licenses": [{"license": {"id": "sha256:deadbeef"}}],
                }
            ]
        }
        stats = merge_syft_licenses_into_trivy(trivy, syft)
        self.assertEqual(stats["enriched"], 0)
        self.assertNotIn("licenses", trivy["components"][0])

    def test_should_enrich_filesystem_only(self):
        self.assertTrue(should_enrich_filesystem_licenses("filesystem .", True))
        self.assertTrue(should_enrich_filesystem_licenses("fs ./src", True))
        self.assertFalse(should_enrich_filesystem_licenses("filesystem .", False))
        self.assertFalse(should_enrich_filesystem_licenses("image nginx:latest", True))
        self.assertFalse(should_enrich_filesystem_licenses("rootfs /tmp/rootfs", True))

    def test_syft_scan_source_native_and_docker(self):
        self.assertEqual(syft_scan_source("filesystem .", False), "dir:.")
        self.assertEqual(syft_scan_source("filesystem ./src", False), "dir:./src")
        self.assertEqual(syft_scan_source("filesystem .", True), "dir:/workdir")
        self.assertEqual(syft_scan_source("fs ./src", True), "dir:/workdir/src")

    def test_syft_release_asset_names(self):
        self.assertEqual(
            syft_release_asset("Linux", "x86_64"),
            f"syft_{SYFT_VERSION}_linux_amd64.tar.gz",
        )
        self.assertEqual(
            syft_release_asset("Darwin", "arm64"),
            f"syft_{SYFT_VERSION}_darwin_arm64.tar.gz",
        )
        self.assertEqual(
            syft_release_asset("Windows", "x86_64"),
            f"syft_{SYFT_VERSION}_windows_amd64.zip",
        )


class TestEnrichLicensesFlag(unittest.TestCase):
    def test_enrich_licenses_cli_flag_default_off(self):
        import argparse

        from aspm_cli.scanners.container_scanner import ContainerScanner as ScannerStrategy

        parser = argparse.ArgumentParser()
        ScannerStrategy().add_arguments(parser)
        args = parser.parse_args(["--command", "filesystem ."])
        self.assertFalse(args.enrich_licenses)
        args = parser.parse_args(
            ["--command", "filesystem .", "--generate-sbom", "--enrich-licenses"]
        )
        self.assertTrue(args.enrich_licenses)
        self.assertTrue(args.generate_sbom)

    def test_enrich_licenses_ignored_for_image(self):
        scanner = ContainerScanner(
            "image nginx:latest",
            generate_sbom=True,
            enrich_licenses=True,
        )
        with patch.object(scanner, "_run_syft") as mock_syft:
            rc = scanner._enrich_licenses_from_syft()
        self.assertEqual(rc, 0)
        mock_syft.assert_not_called()

    def test_enrich_licenses_ignored_for_rootfs(self):
        scanner = ContainerScanner(
            "rootfs /tmp/rootfs",
            generate_sbom=True,
            enrich_licenses=True,
        )
        with patch.object(scanner, "_run_syft") as mock_syft:
            rc = scanner._enrich_licenses_from_syft()
        self.assertEqual(rc, 0)
        mock_syft.assert_not_called()

    def test_build_syft_command_container_mode(self):
        scanner = ContainerScanner(
            "filesystem .",
            container_mode=True,
            generate_sbom=True,
            enrich_licenses=True,
        )
        cmd = scanner._build_syft_command()
        self.assertIn("docker", cmd)
        self.assertIn(scanner.ak_syft_image, cmd)
        self.assertIn("dir:/workdir", cmd)
        self.assertIn("--enrich", cmd)
        self.assertIn("cyclonedx-json=/workdir/.accuknox-syft-sbom.json", cmd)

    def test_missing_syft_fails(self):
        scanner = ContainerScanner(
            "filesystem .",
            generate_sbom=True,
            enrich_licenses=True,
        )
        with patch.object(scanner, "_run_syft", side_effect=FileNotFoundError("missing")):
            rc = scanner._enrich_licenses_from_syft()
        self.assertEqual(rc, 1)

    def test_syft_runtime_failure_keeps_trivy(self):
        scanner = ContainerScanner(
            "filesystem .",
            generate_sbom=True,
            enrich_licenses=True,
        )
        with patch.object(scanner, "_run_syft", return_value=1):
            rc = scanner._enrich_licenses_from_syft()
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
