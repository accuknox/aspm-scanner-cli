import argparse
import io
import json
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from aspm_cli.utils.artifact_engine import (
    ArtifactError, detect_target, extract_archive, fingerprint, result_exit_code, scan_artifact,
)
from aspm_cli.commands.scan_command import ScanCommand


class ArtifactScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "my application"
        self.binary.write_bytes(b"\x7fELF" + b"fixture")
        self.calls = []

    def executor(self, tool, args, work):
        self.calls.append((tool, args))
        if tool == "syft":
            output = next(arg.split("=", 1)[1] for arg in args if arg.startswith("cyclonedx-json="))
            Path(output).write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {"component": {"type": "application", "name": "test"}},
                "components": [{"type": "library", "name": "example", "version": "1.0", "purl": "pkg:npm/example@1.0"}]}))
        else:
            output = args[args.index("--output") + 1]
            Path(output).write_text(json.dumps({"SchemaVersion": 2, "ArtifactType": "sbom", "ArtifactName": "test",
                "Results": [{"Target": "test", "Vulnerabilities": [{"VulnerabilityID": "CVE-2020-0001", "PkgName": "example", "Severity": "HIGH"}]}]}))

    def test_binary_uses_inventory_then_sbom_without_executing_input(self):
        before = self.binary.read_bytes()
        result = scan_artifact(self.binary, self.root / "out", execute=self.executor)
        self.assertEqual(self.calls[0][0], "syft")
        self.assertEqual(self.calls[1][1][0], "sbom")
        self.assertEqual(result["coverage"], "limited")
        self.assertEqual(result["finding_counts"], {"HIGH": 1})
        self.assertEqual(self.binary.read_bytes(), before)
        self.assertEqual(result_exit_code(result, {"HIGH"}), 1)
        self.assertEqual(result_exit_code(result, {"CRITICAL"}), 0)
        self.assertEqual(result_exit_code(result, {"HIGH"}, True), 0)

    def test_manifest_selection_is_exact_and_does_not_scan_parent(self):
        manifest = self.root / "requirements.txt"
        manifest.write_text("requests==2.0.0\n")
        result = scan_artifact(manifest, self.root / "out", execute=self.executor)
        args = self.calls[1][1]
        self.assertEqual(args[:2], ["fs", str(manifest.resolve())])
        self.assertEqual(result["coverage"], "complete")

    def test_existing_spdx_is_converted_before_vulnerability_scan(self):
        target = self.root / "bom.json"
        target.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}))
        scan_artifact(target, self.root / "out", execute=self.executor)
        self.assertEqual(self.calls[0][1][0], "convert")
        self.assertEqual(self.calls[1][1][0], "sbom")

    def test_operational_failure_is_not_softfailed_and_preserves_inventory(self):
        def executor(tool, args, work):
            if tool == "trivy":
                raise ArtifactError("Database unavailable")
            self.executor(tool, args, work)
        result = scan_artifact(self.binary, self.root / "out", execute=executor)
        self.assertEqual(result["status"], "partial")
        self.assertIsNotNone(result["sbom"])
        self.assertEqual(result_exit_code(result, {"HIGH"}, True), 2)

    def test_successful_vulnerability_stage_survives_inventory_failure(self):
        target = self.root / "requirements.txt"
        target.write_text("requests==2.0.0")
        def executor(tool, args, work):
            if tool == "syft":
                raise ArtifactError("Inventory unavailable")
            self.executor(tool, args, work)
        result = scan_artifact(target, self.root / "out", execute=executor)
        self.assertEqual(result["status"], "partial")
        self.assertIsNotNone(result["vulnerability_report"])
        self.assertEqual(result_exit_code(result, {"HIGH"}, True), 2)

    def test_empty_inventory_is_incomplete_not_clean(self):
        def executor(tool, args, work):
            self.executor(tool, args, work)
            if tool == "syft":
                output = next(arg.split("=", 1)[1] for arg in args if arg.startswith("cyclonedx-json="))
                doc = json.loads(Path(output).read_text()); doc["components"] = []
                Path(output).write_text(json.dumps(doc))
        result = scan_artifact(self.binary, self.root / "out", execute=executor)
        self.assertEqual(result["coverage"], "limited")
        self.assertEqual(result_exit_code(result, {"HIGH"}, True), 2)

    def test_directory_rejects_outputs_inside_input(self):
        with self.assertRaises(ArtifactError):
            scan_artifact(self.root, self.root / "out", execute=self.executor)
        self.assertEqual(self.calls, [])

    def test_unknown_binary_and_apk_are_not_silently_scanned_as_source(self):
        for filename, contents in [("test.bin", b"garbage"), ("test.apk", b"PKxx")]:
            path = self.root / filename; path.write_bytes(contents)
            with self.assertRaises(ArtifactError):
                detect_target(path)

    def test_repeated_builds_keep_name_but_have_different_digest(self):
        a = scan_artifact(self.binary, self.root / "out1", asset_name="service", execute=self.executor)
        self.binary.write_bytes(b"\x7fELFnew")
        b = scan_artifact(self.binary, self.root / "out2", asset_name="service", execute=self.executor)
        self.assertEqual(a["artifact"]["name"], b["artifact"]["name"])
        self.assertNotEqual(a["artifact"]["sha256"], b["artifact"]["sha256"])

    def test_archive_paths_links_duplicates_and_expansion(self):
        for name in ["../outside", "/outside", "C:/outside", "x\\outside"]:
            archive = self.root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as output:
                info = zipfile.ZipInfo("placeholder")
                info.filename = name  # ZipInfo() rewrites "\\" to "/" on Windows; keep the raw name
                output.writestr(info, "bad")
            with self.assertRaises(ArtifactError):
                extract_archive(archive, self.root / "extract")
        archive = self.root / "link.zip"
        member = zipfile.ZipInfo("link"); member.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr(member, "/tmp/target")
        with self.assertRaises(ArtifactError):
            extract_archive(archive, self.root / "extract")
        archive = self.root / "duplicate.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("A", "a"); output.writestr("a", "a")
        with self.assertRaises(ArtifactError):
            extract_archive(archive, self.root / "extract")
        archive = self.root / "large.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("file", "larger than limit")
        with patch("aspm_cli.utils.artifact_engine.MAX_EXPANDED", 1), self.assertRaises(ArtifactError):
            extract_archive(archive, self.root / "extract")

    def test_tar_hardlinks_are_rejected(self):
        archive = self.root / "bad.tar"
        with tarfile.open(archive, "w") as output:
            member = tarfile.TarInfo("escape"); member.type = tarfile.LNKTYPE; member.linkname = "../x"
            output.addfile(member)
        with self.assertRaises(ArtifactError):
            extract_archive(archive, self.root / "extract")

    def test_directory_fingerprint_is_independent_of_host_location(self):
        a = self.root / "a"; b = self.root / "b"; a.mkdir(); b.mkdir()
        (a / "go.mod").write_text("module example"); (b / "go.mod").write_text("module example")
        self.assertEqual(fingerprint(a), fingerprint(b))

    def test_cli_target_and_legacy_command_are_mutually_exclusive(self):
        parser = argparse.ArgumentParser(); ScanCommand().configure_parser(parser)
        with self.assertRaises(SystemExit):
            parser.parse_args(["sca", "--target", str(self.binary), "--command", "fs ."])
        with self.assertRaises(SystemExit):
            parser.parse_args(["sca"])
        self.assertEqual(parser.parse_args(["sca", "--command", "fs ."]).command, "fs .")


if __name__ == "__main__":
    unittest.main()
