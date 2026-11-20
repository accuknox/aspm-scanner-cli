"""Binary, archive and container-image targets for the local artifact engine."""
import gzip
import io
import json
import os
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from aspm_cli.utils import artifact_engine as engine
from aspm_cli.utils.artifact_engine import (
    ArtifactError, Limits, append_missing_components, detect_format, detect_target, extract_archive, extract_external,
    extract_nested, mark_executables, merge_trivy_reports, parse_7z_listing, parse_bsdtar_listing,
    prepare_scan_input, scan_artifact, trivy_passes,
)

ELF = b"\x7fELF" + b"\0" * 60


def vuln(vid="CVE-2020-0001", pkg="example", version="1.0", purl="pkg:npm/example@1.0", severity="HIGH"):
    return {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": version, "Severity": severity,
            "PkgIdentifier": {"PURL": purl}}


def report(*vulns, artifact_type="filesystem", packages=None):
    entry = {"Target": "t", "Type": "npm", "Vulnerabilities": list(vulns)}
    if packages:
        entry["Packages"] = packages
    return {"SchemaVersion": 2, "ArtifactType": artifact_type, "ArtifactName": "x", "Results": [entry]}


def add_tar_file(archive, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []
        self.trivy_reports = {}

    def docker_tar(self, name="image.tar", compress=False):
        path = self.root / name
        manifest = json.dumps([{"Config": "c.json", "Layers": ["l/layer.tar"], "RepoTags": ["x:1"]}]).encode()
        with tarfile.open(path, "w:gz" if compress else "w") as archive:
            add_tar_file(archive, "manifest.json", manifest)
            add_tar_file(archive, "c.json", b"{}")
            add_tar_file(archive, "l/layer.tar", b"layer")
        return path

    def executor(self, tool, args, work):
        self.calls.append((tool, list(args)))
        if tool == "syft":
            output = next(a.split("=", 1)[1] for a in args if a.startswith("cyclonedx-json="))
            Path(output).write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": {"component": {"type": "application", "name": "t", "bom-ref": "root"}},
                "components": [{"type": "library", "name": "example", "version": "1.0",
                                "purl": "pkg:npm/example@1.0", "bom-ref": "pkg:npm/example@1.0"}]}))
            return
        name = args[0]
        if isinstance(self.trivy_reports.get(name), Exception):
            raise self.trivy_reports[name]
        doc = self.trivy_reports.get(name) or report(vuln(), artifact_type="cyclonedx" if name == "sbom" else "filesystem")
        Path(args[args.index("--output") + 1]).write_text(json.dumps(doc))

    def trivy_calls(self):
        return [args for tool, args in self.calls if tool == "trivy"]


class FormatDetectionTests(Base):
    def test_docker_and_oci_archives_are_images_but_other_tars_are_not(self):
        self.assertEqual(detect_format(self.docker_tar()), "docker-archive")
        oci = self.root / "oci.tar"
        with tarfile.open(oci, "w") as archive:
            add_tar_file(archive, "oci-layout", b"{}")
            add_tar_file(archive, "index.json", b"{}")
        self.assertEqual(detect_format(oci), "oci-archive")
        fake = self.root / "fake.tar"
        with tarfile.open(fake, "w") as archive:
            add_tar_file(archive, "manifest.json", b'{"name": "a chrome extension"}')
        self.assertEqual(detect_format(fake), "tar")

    def test_oci_layout_directory_is_an_archive_target(self):
        layout = self.root / "layout"
        layout.mkdir()
        (layout / "oci-layout").write_text("{}")
        (layout / "index.json").write_text("{}")
        self.assertEqual(detect_format(layout), "oci-layout")
        self.assertEqual(detect_target(layout), "archive")
        self.assertEqual(detect_target(self.root / "layout", "auto"), "archive")

    def test_compressed_single_files_and_external_formats_are_archives(self):
        compressed = self.root / "app.gz"
        compressed.write_bytes(gzip.compress(ELF))
        self.assertEqual((detect_format(compressed), detect_target(compressed)), ("gzip", "archive"))
        sevenzip = self.root / "a.7z"
        sevenzip.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 32)
        rar = self.root / "a.rar"
        rar.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"\0" * 32)
        self.assertEqual((detect_format(sevenzip), detect_target(sevenzip)), ("7z", "archive"))
        self.assertEqual((detect_format(rar), detect_target(rar)), ("rar", "archive"))

    def test_alpine_apk_is_scannable_but_android_apk_is_not(self):
        alpine = self.root / "pkg.apk"
        with tarfile.open(alpine, "w:gz") as archive:
            add_tar_file(archive, ".PKGINFO", b"pkgname = x\n")
        self.assertEqual(detect_target(alpine), "archive")
        android = self.root / "app.apk"
        with zipfile.ZipFile(android, "w") as archive:
            archive.writestr("AndroidManifest.xml", "<manifest/>")
        with self.assertRaisesRegex(ArtifactError, "mobile scanner"):
            detect_target(android)

    def test_size_limit_is_a_parameter(self):
        big = self.root / "big"
        big.write_bytes(ELF)
        with self.assertRaisesRegex(ArtifactError, "size limit"):
            detect_target(big, "auto", 10)
        self.assertEqual(detect_target(big, "auto", 1024), "binary")


class TrivyPassTests(Base):
    def test_directory_runs_inventory_then_fs_and_rootfs(self):
        tree = self.root / "tree"
        tree.mkdir()
        (tree / "requirements.txt").write_text("requests==2.0.0\n")
        result = scan_artifact(tree, self.root / "out", execute=self.executor)
        self.assertEqual([args[0] for args in self.trivy_calls()], ["sbom", "fs", "rootfs"])
        self.assertEqual(result["finding_counts"], {"HIGH": 1})  # identical findings are not double counted
        self.assertEqual(result["stages"]["vulnerabilities"]["status"], "completed")

    def test_binary_file_gets_rootfs_not_fs(self):
        binary = self.root / "tool"
        binary.write_bytes(ELF)
        binary.chmod(0o755)
        scan_artifact(binary, self.root / "out", execute=self.executor)
        passes = {args[0]: args for args in self.trivy_calls()}
        self.assertEqual(set(passes), {"sbom", "rootfs"})
        self.assertEqual(passes["rootfs"][1], str(binary.resolve()))

    def test_non_executable_binary_is_staged_without_touching_the_input(self):
        binary = self.root / "tool.exe"
        binary.write_bytes(b"MZ" + b"\0" * 60)
        binary.chmod(0o644)
        scan_artifact(binary, self.root / "out", execute=self.executor)
        rootfs = next(a for a in self.trivy_calls() if a[0] == "rootfs")
        staged = Path(rootfs[1])
        self.assertEqual(staged.parent.name, "staged")
        self.assertTrue(os.access(staged, os.X_OK))
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o644)

    def test_container_image_is_not_extracted_and_uses_image_input(self):
        image = self.docker_tar()
        result = scan_artifact(image, self.root / "out", execute=self.executor)
        syft = next(args for tool, args in self.calls if tool == "syft")
        self.assertEqual(syft[1], f"docker-archive:{image.resolve()}")
        native = next(a for a in self.trivy_calls() if a[0] == "image")
        self.assertEqual(native[1:3], ["--input", str(image.resolve())])
        self.assertFalse((self.root / "out" / "contents").exists())
        self.assertEqual((result["artifact"]["type"], result["artifact"]["format"]), ("archive", "docker-archive"))

    def test_gzipped_image_is_decompressed_once_for_the_scanners(self):
        image = self.docker_tar("image.tar.gz", compress=True)
        scan_artifact(image, self.root / "out", execute=self.executor)
        native = next(a for a in self.trivy_calls() if a[0] == "image")
        self.assertTrue(native[2].endswith("image.tar"))
        self.assertNotEqual(Path(native[2]).resolve(), image.resolve())

    def test_oci_layout_directory_uses_oci_dir_source(self):
        layout = self.root / "layout"
        layout.mkdir()
        (layout / "oci-layout").write_text("{}")
        (layout / "index.json").write_text("{}")
        scan_artifact(layout, self.root / "out", execute=self.executor)
        syft = next(args for tool, args in self.calls if tool == "syft")
        self.assertTrue(syft[1].startswith("oci-dir:"))

    def test_single_failed_extra_pass_is_a_coverage_reason_not_a_failure(self):
        self.trivy_reports["rootfs"] = ArtifactError("rootfs boom")
        binary = self.root / "tool"
        binary.write_bytes(ELF)
        binary.chmod(0o755)
        result = scan_artifact(binary, self.root / "out", execute=self.executor)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(any("rootfs vulnerability scan failed: rootfs boom" in r for r in result["coverage_reasons"]))
        self.assertEqual(result["coverage"], "limited")

    def test_all_passes_failing_fails_the_stage_and_keeps_the_inventory(self):
        self.trivy_reports.update(sbom=ArtifactError("db down"), rootfs=ArtifactError("db down"))
        binary = self.root / "tool"
        binary.write_bytes(ELF)
        binary.chmod(0o755)
        result = scan_artifact(binary, self.root / "out", execute=self.executor)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["stages"]["vulnerabilities"]["status"], "failed")
        self.assertIsNotNone(result["sbom"])

    def test_envelope_stays_compatible_with_the_backend_contract(self):
        image = self.docker_tar()
        result = scan_artifact(image, self.root / "out", execute=self.executor)
        self.assertIn(result["artifact"]["type"], engine.TARGET_TYPES[1:])
        self.assertTrue(all(s["status"] in {"completed", "failed"} for s in result["stages"].values()))
        self.assertEqual(result["schema_version"], 1)
        json.dumps(result)

    def test_passes_by_kind(self):
        bom = self.root / "sbom.json"
        manifest = self.root / "go.mod"
        manifest.write_text("module x")
        self.assertEqual([n for n, _ in trivy_passes("manifest", manifest, None, bom)], ["fs"])
        self.assertEqual([n for n, _ in trivy_passes("sbom", manifest, None, bom)], ["sbom"])
        self.assertEqual([n for n, _ in trivy_passes("archive", manifest, "docker-archive", bom)], ["sbom", "image"])


class MergeTests(unittest.TestCase):
    def test_versions_differing_only_by_v_prefix_are_one_finding(self):
        merged = merge_trivy_reports([
            report(vuln(pkg="stdlib", version="1.27.1", purl="pkg:golang/stdlib@1.27.1"), artifact_type="cyclonedx"),
            report(vuln(pkg="stdlib", version="v1.27.1", purl="pkg:golang/stdlib@v1.27.1")),
        ])
        findings = [v for e in merged["Results"] for v in e.get("Vulnerabilities", [])]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["PkgIdentifier"]["PURL"], "pkg:golang/stdlib@1.27.1")  # inventory record wins
        self.assertEqual(merged["ArtifactType"], "cyclonedx")

    def test_distinct_advisories_and_versions_are_kept(self):
        merged = merge_trivy_reports([
            report(vuln("CVE-1", version="1.0")), report(vuln("CVE-2", version="1.0"), vuln("CVE-1", version="2.0"))])
        self.assertEqual(sum(len(e.get("Vulnerabilities", [])) for e in merged["Results"]), 3)

    def test_results_without_findings_or_packages_are_dropped(self):
        merged = merge_trivy_reports([report(vuln()), report(vuln())])
        self.assertEqual(len(merged["Results"]), 1)

    def test_native_only_findings_get_a_component_so_they_map(self):
        bom = {"metadata": {"component": {"bom-ref": "root"}},
               "components": [{"name": "a", "version": "1", "purl": "pkg:apk/alpine/a@1?distro=x", "bom-ref": "a"}],
               "dependencies": [{"ref": "root", "dependsOn": ["a"]}]}
        rep = report(vuln(pkg="a", version="1", purl="pkg:apk/alpine/a@1?distro=x"),
                     vuln("CVE-9", pkg="b", version="2", purl="pkg:apk/alpine/b@2?distro=3.21"))
        self.assertEqual(append_missing_components(bom, rep), 1)
        added = bom["components"][-1]
        self.assertEqual((added["purl"], added["version"]), ("pkg:apk/alpine/b@2?distro=3.21", "2"))
        root = next(d for d in bom["dependencies"] if d["ref"] == "root")
        self.assertIn(added["bom-ref"], root["dependsOn"])
        self.assertEqual(append_missing_components(bom, rep), 0)  # idempotent


class ExtractionTests(Base):
    def make_zip(self, path, members):
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return path

    def test_nested_archives_are_unpacked_once_and_replaced(self):
        inner = self.make_zip(self.root / "inner.zip", {"deep/tool": ELF})
        outer = self.make_zip(self.root / "outer.zip", {"inner.zip": inner.read_bytes(), "readme.txt": b"hi"})
        scan_path, scan_kind, image, notes = prepare_scan_input(
            outer, "archive", detect_format(outer), self.root / "out", Limits())
        self.assertEqual((scan_kind, image, notes), ("directory", None, []))
        self.assertFalse((scan_path / "inner.zip").exists())
        extracted = scan_path / "inner.zip.extracted" / "deep" / "tool"
        self.assertTrue(extracted.is_file())
        self.assertTrue(os.access(extracted, os.X_OK))  # needed by Trivy's binary analyzers

    def test_jars_and_documents_inside_archives_are_left_alone(self):
        jar = self.make_zip(self.root / "a.jar", {"META-INF/MANIFEST.MF": "x"})
        outer = self.make_zip(self.root / "outer.zip", {"lib/a.jar": jar.read_bytes()})
        scan_path, *_ = prepare_scan_input(outer, "archive", "zip", self.root / "out", Limits())
        self.assertTrue((scan_path / "lib" / "a.jar").is_file())

    def test_nested_depth_is_capped_with_a_note(self):
        data = b"payload"
        for level in range(engine.MAX_NEST_DEPTH + 2):
            path = self.root / f"l{level}.zip"
            self.make_zip(path, {"x.txt" if level == 0 else f"l{level - 1}.zip": data})
            data = path.read_bytes()
        scan_path, _, _, notes = prepare_scan_input(path, "archive", "zip", self.root / "out", Limits())
        self.assertTrue(any("nested deeper" in n for n in notes))

    def test_unsafe_member_in_a_nested_archive_is_reported_not_fatal(self):
        evil = self.make_zip(self.root / "evil.zip", {"../escape.txt": "x"})
        outer = self.make_zip(self.root / "outer.zip", {"evil.zip": evil.read_bytes(), "ok.txt": "ok"})
        scan_path, _, _, notes = prepare_scan_input(outer, "archive", "zip", self.root / "out", Limits())
        self.assertTrue(any("evil.zip" in n and "Unsafe archive path" in n for n in notes))
        self.assertFalse((self.root / "out" / "escape.txt").exists())
        self.assertFalse((scan_path.parent / "escape.txt").exists())

    def test_many_nested_failures_are_summarised(self):
        evil = self.make_zip(self.root / "evil.zip", {"../x": "x"}).read_bytes()
        outer = self.make_zip(self.root / "outer.zip", {f"e{i}.zip": evil for i in range(engine.MAX_NOTES + 5)})
        calls = []
        result = scan_artifact(outer, self.root / "out", execute=self.executor)
        reasons = [r for r in result["coverage_reasons"] if "nested" in r.lower() or "Nested" in r]
        self.assertEqual(len([r for r in reasons if r.startswith("Nested archive")]), engine.MAX_NOTES)
        self.assertTrue(any("5 more nested archives" in r for r in reasons))

    def test_expansion_budget_is_shared_across_nesting(self):
        inner = self.make_zip(self.root / "inner.zip", {"a": "x" * 600})
        outer = self.make_zip(self.root / "outer.zip", {"inner.zip": inner.read_bytes(), "b": "x" * 50})
        with patch.object(engine, "MAX_EXPANDED", 1000):
            _, _, _, notes = prepare_scan_input(outer, "archive", "zip", self.root / "out", Limits())
        self.assertTrue(any("expansion limits" in n for n in notes))

    def test_compressed_binary_is_decompressed_and_made_executable(self):
        packed = self.root / "app.gz"
        packed.write_bytes(gzip.compress(ELF))
        scan_path, scan_kind, _, _ = prepare_scan_input(packed, "archive", "gzip", self.root / "out", Limits())
        self.assertEqual(scan_kind, "binary")
        self.assertEqual(scan_path.read_bytes(), ELF)
        self.assertTrue(os.access(scan_path, os.X_OK))

    def test_decompression_bomb_is_stopped_by_the_budget(self):
        packed = self.root / "bomb.gz"
        packed.write_bytes(gzip.compress(ELF + b"\0" * 5_000_000))
        with self.assertRaisesRegex(ArtifactError, "expansion limits"):
            prepare_scan_input(packed, "archive", "gzip", self.root / "out", Limits(max_expanded=1_000_000))

    def test_corrupt_compressed_file_is_a_clean_error(self):
        broken = self.root / "broken.gz"
        broken.write_bytes(b"\x1f\x8b" + b"garbage")
        with self.assertRaisesRegex(ArtifactError, "corrupt"):
            prepare_scan_input(broken, "archive", "gzip", self.root / "out", Limits())

    def test_library_errors_become_artifact_errors_for_the_backend_upload_check(self):
        corrupt = self.root / "corrupt.zip"
        corrupt.write_bytes(b"PK\x03\x04" + b"garbage" * 4)
        with self.assertRaises(ArtifactError):
            extract_archive(corrupt, self.root / "d1")
        truncated = self.root / "t.tar.gz"
        with tarfile.open(truncated, "w:gz") as archive:
            add_tar_file(archive, "a", b"x" * 100000)
        truncated.write_bytes(truncated.read_bytes()[:60])
        with self.assertRaises(ArtifactError):
            extract_archive(truncated, self.root / "d2")
        with self.assertRaisesRegex(ArtifactError, "corrupt"):
            detect_target(truncated)
        bare = self.root / "bare.gz"
        bare.write_bytes(gzip.compress(b"just text"))
        with self.assertRaisesRegex(ArtifactError, "Unsupported archive type"):
            extract_archive(bare, self.root / "d3")

    def test_mark_executables_only_touches_executables(self):
        (self.root / "t").mkdir()
        (self.root / "t" / "bin").write_bytes(ELF)
        (self.root / "t" / "note.txt").write_text("hello")
        for f in (self.root / "t").iterdir():
            f.chmod(0o644)
        mark_executables(self.root / "t")
        self.assertTrue(os.access(self.root / "t" / "bin", os.X_OK))
        self.assertFalse(os.access(self.root / "t" / "note.txt", os.X_OK))


class ExternalArchiveTests(Base):
    SEVENZ = ("Path = a/app\nSize = 10\nFolder = -\nAttributes = A -rwxr-xr-x\nEncrypted = -\n\n"
              "Path = a\nSize = 0\nFolder = +\nAttributes = D drwxr-xr-x\nEncrypted = -\n")

    def test_7z_listing_is_parsed(self):
        self.assertEqual(parse_7z_listing(self.SEVENZ), [("a/app", 10, False), ("a", 0, True)])

    def test_7z_links_devices_and_encryption_are_rejected(self):
        for block in ("Path = l\nSize = 0\nAttributes = A lrwxrwxrwx\n", "Path = c\nSize = 0\nAttributes = A crw-r--r--\n",
                      "Path = s\nSize = 1\nSymbolic Link = /etc/passwd\n", "Path = e\nSize = 1\nEncrypted = +\n"):
            with self.assertRaises(ArtifactError, msg=block):
                parse_7z_listing(block)

    def test_bsdtar_listing_is_parsed_in_both_date_orders(self):
        text = ("-rw-r--r--  0 0      0           9 17 Nov 17:26 ./with space.txt\n"
                "drwxr-xr-x  0 0      0           0 Nov 17  2024 ./sub/\n")
        self.assertEqual(parse_bsdtar_listing(text), [("./with space.txt", 9, False), ("./sub/", 0, True)])
        with self.assertRaises(ArtifactError):
            parse_bsdtar_listing("lrwxr-xr-x  0 0      0           0 17 Nov 17:26 ./l -> /etc/passwd\n")
        with self.assertRaisesRegex(ArtifactError, "not understood"):
            parse_bsdtar_listing("surprising format\n")

    def run_external(self, listing, extract=None, flavour="7zz"):
        calls = []
        class Done:
            def __init__(self, out=b""):
                self.stdout = out
        def fake_run(command, **kwargs):
            calls.append(command)
            if command[1] in {"l", "-tvf"}:
                return Done(listing.encode())
            if extract:
                extract(Path(next(a[2:] for a in command if a.startswith("-o"))) if flavour == "7zz"
                        else Path(command[command.index("-C") + 1]))
            return Done()
        archive = self.root / "a.7z"
        archive.write_bytes(b"7z\xbc\xaf\x27\x1c")
        with patch.object(engine.shutil, "which", lambda n: f"/usr/bin/{n}" if n == flavour else None), \
                patch.object(engine.subprocess, "run", fake_run):
            return calls, extract_external(archive, self.root / "dest", Limits())

    def test_listing_is_validated_before_anything_is_extracted(self):
        calls, _ = self.run_external(self.SEVENZ, lambda dest: (dest / "a").mkdir(parents=True) or (dest / "a" / "app").write_text("x" * 10))
        self.assertEqual([c[1] for c in calls], ["l", "x"])
        engine.shutil.rmtree(self.root / "dest")
        with self.assertRaisesRegex(ArtifactError, "Unsafe archive path"):
            self.run_external("Path = ../evil\nSize = 1\nAttributes = A -rw-r--r--\n")
        # nothing was extracted for the unsafe listing
        self.assertFalse((self.root / "dest" / "evil").exists())

    def test_declared_size_over_budget_is_refused_before_extraction(self):
        called = []
        with self.assertRaisesRegex(ArtifactError, "expansion limits"):
            with patch.object(engine, "MAX_EXPANDED", 5):
                self.run_external(self.SEVENZ, lambda dest: called.append(dest))
        self.assertEqual(called, [])

    def test_a_link_created_by_the_extractor_is_still_rejected_and_cleaned_up(self):
        def evil(dest):
            dest.mkdir(parents=True, exist_ok=True)
            os.symlink("/etc/passwd", dest / "a")
        with self.assertRaisesRegex(ArtifactError, "links and special files"):
            self.run_external("Path = a\nSize = 1\nAttributes = A -rw-r--r--\n", evil)
        self.assertFalse((self.root / "dest").exists())

    def test_missing_extractor_explains_what_to_install(self):
        archive = self.root / "a.rar"
        archive.write_bytes(b"Rar!\x1a\x07\x01\x00")
        with patch.object(engine.shutil, "which", lambda n: None), self.assertRaisesRegex(ArtifactError, "7-Zip.*bsdtar"):
            extract_external(archive, self.root / "dest", Limits())

    def test_bsdtar_is_used_when_7zip_is_absent(self):
        listing = "-rw-r--r--  0 0      0          10 17 Nov 17:26 app\n"
        def extract(dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "app").write_text("x" * 10)
        calls, _ = self.run_external(listing, extract, flavour="bsdtar")
        self.assertEqual(calls[0][:2], ["/usr/bin/bsdtar", "-tvf"])
        self.assertIn("--no-same-owner", calls[1])

    def test_nested_7z_failure_is_a_note(self):
        outer = self.root / "outer.zip"
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("inner.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 20)
            archive.writestr("ok.txt", "ok")
        notes = []
        with patch.object(engine.shutil, "which", lambda n: None):
            _, _, _, notes = prepare_scan_input(outer, "archive", "zip", self.root / "out", Limits())
        self.assertTrue(any("inner.7z" in n and "external extractor" in n for n in notes))


if __name__ == "__main__":
    unittest.main()


class ArtifactClientErrorTests(unittest.TestCase):
    """The upload client must say *why* a request failed, without leaking the token."""

    def client(self, outcome):
        from aspm_cli.scan.artifact import ArtifactClient
        client = ArtifactClient({"accuknox_endpoint": "http://127.0.0.1:8010", "accuknox_token": "SECRET-TOKEN",
                                 "accuknox_tenant": 2})
        def fake_request(*args, **kwargs):
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        client.session.request = fake_request
        return client

    def response(self, status, body):
        import requests
        reply = requests.Response()
        reply.status_code = status
        reply._content = json.dumps(body).encode() if not isinstance(body, bytes) else body
        return reply

    def message(self, outcome):
        with self.assertRaises(ArtifactError) as caught:
            self.client(outcome).capabilities()
        return str(caught.exception)

    def test_http_errors_include_status_and_server_reason(self):
        text = self.message(self.response(401, {"detail": "Given token not valid for any token type"}))
        self.assertIn("HTTP 401", text)
        self.assertIn("Given token not valid", text)
        self.assertIn("ACCUKNOX_TOKEN", text)
        text = self.message(self.response(403, {"detail": "You do not have permission to perform this action."}))
        self.assertIn("HTTP 403", text)
        self.assertIn("ACCUKNOX_TENANT", text)

    def test_non_json_error_bodies_are_truncated(self):
        text = self.message(self.response(500, b"<html>" + b"x" * 5000))
        self.assertIn("HTTP 500", text)
        self.assertLess(len(text), 500)

    def test_connection_and_tls_failures_are_distinguished(self):
        import requests
        self.assertIn("Cannot connect to the artifact API at http://127.0.0.1:8010",
                      self.message(requests.ConnectionError("refused")))
        self.assertIn("TLS error", self.message(requests.exceptions.SSLError("bad cert")))
        self.assertIn("timed out", self.message(requests.Timeout("slow")))

    def test_the_token_never_appears_in_messages(self):
        import requests
        for outcome in (self.response(401, {"detail": "no"}), requests.ConnectionError("SECRET-TOKEN refused")):
            self.assertNotIn("SECRET-TOKEN", self.message(outcome))

    def test_missing_route_keeps_its_upgrade_message(self):
        self.assertIn("does not support artifact scans", self.message(self.response(404, {})))


class LegacyUploadTests(unittest.TestCase):
    """sca/sbom --target uploads use /api/v1/artifact/ (TR / SBOM), the route SAST/SCA/DAST use."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / "out"
        self.uploads = []

    def result(self, components=True, report=True):
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "project_name": "proj",
               "metadata": {"component": {"name": "app", "bom-ref": "root"},
                                "tools": {"components": [{"type": "application", "author": "anchore", "name": "syft", "version": "1.42.3"}]}},
               "components": [{"type": "library", "name": "a", "version": "1", "purl": "pkg:npm/a@1"}] if components else []}
        vulns = {"SchemaVersion": 2, "ArtifactType": "cyclonedx", "ArtifactName": "/tmp/x/sbom.json", "Trivy": {"Version": "0.69"},
                 "Results": [{"Target": "t", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "a", "Severity": "HIGH"}]}]}
        return {"schema_version": 1, "status": "completed", "component_count": int(components), "finding_counts": {"HIGH": 1},
                "artifact": {"name": "app.zip", "type": "archive"}, "sbom": bom, "vulnerability_report": vulns if report else None}

    def run_execute(self, mode, config=None, scan_result=None, upload_code=0, **overrides):
        from argparse import Namespace
        from aspm_cli.scan import artifact
        args = Namespace(scantype=mode, skip_upload=False, target=str(self.out.parent / "app.zip"), target_type="auto",
                         asset_name=overrides.get("asset_name"), output_dir=str(self.out), container_mode=False, cache_dir=None,
                         offline=True, keep_results=True, run_id=None, idempotency_key=None, severity="HIGH,CRITICAL")
        config = config or {"accuknox_endpoint": "http://x", "accuknox_token": "tok", "accuknox_label": "lbl",
                            "accuknox_project_name": "proj", "accuknox_tenant": None}
        def fake_upload(path, endpoint, label, token, tenant, data_type, keep_file=False, extra_params=None):
            self.uploads.append({"data": json.load(open(path)), "endpoint": endpoint, "label": label, "token": token,
                                 "tenant": tenant, "type": data_type})
            return upload_code
        def no_client(*a, **k):
            raise AssertionError("the artifact-scans API must not be used for sca/sbom uploads")
        with patch.object(artifact, "scan_artifact", return_value=scan_result or self.result()), \
             patch.object(artifact, "upload_results", fake_upload), patch.object(artifact, "ArtifactClient", no_client):
            return artifact.execute_artifact(args, config, False)

    def test_sca_uploads_the_merged_report_as_a_filesystem_tr(self):
        code = self.run_execute("sca")
        self.assertEqual(code, 1)  # HIGH finding gates, as before
        (upload,) = self.uploads
        self.assertEqual(upload["type"], "TR")
        self.assertEqual((upload["data"]["ArtifactType"], upload["data"]["ArtifactName"]), ("filesystem", "app.zip"))
        self.assertNotIn("Trivy", upload["data"])
        self.assertEqual((upload["label"], upload["token"], upload["tenant"]), ("lbl", "tok", None))

    def test_asset_name_and_optional_tenant_are_passed_through(self):
        config = {"accuknox_endpoint": "http://x", "accuknox_token": "tok", "accuknox_label": "lbl",
                  "accuknox_project_name": None, "accuknox_tenant": 2}
        self.run_execute("sca", config=config, asset_name="java-log4j.jar")  # sca needs no project name
        self.assertEqual(self.uploads[0]["data"]["ArtifactName"], "java-log4j.jar")
        self.assertEqual(self.uploads[0]["tenant"], "2")

    def test_sbom_uploads_a_branded_clean_cyclonedx_under_the_project(self):
        self.run_execute("sbom", scan_result=self.result(report=False))
        (upload,) = self.uploads
        self.assertEqual((upload["type"], upload["data"]["project_name"]), ("SBOM", "proj"))
        self.assertNotIn("syft", json.dumps(upload["data"]).lower())

    def test_empty_sbom_is_not_uploaded(self):
        self.run_execute("sbom", scan_result=self.result(components=False, report=False))
        self.assertEqual(self.uploads, [])

    def test_sbom_needs_a_project_but_sca_does_not(self):
        from aspm_cli.utils.artifact_engine import ArtifactError
        config = {"accuknox_endpoint": "http://x", "accuknox_token": "tok", "accuknox_label": "lbl", "accuknox_project_name": None}
        with self.assertRaisesRegex(ArtifactError, "project name"):
            self.run_execute("sbom", config=config)

    def test_label_is_required(self):
        from aspm_cli.utils.artifact_engine import ArtifactError
        config = {"accuknox_endpoint": "http://x", "accuknox_token": "tok", "accuknox_label": None}
        with self.assertRaisesRegex(ArtifactError, "label"):
            self.run_execute("sca", config=config)

    def test_a_rejected_upload_is_an_error_and_results_are_kept(self):
        from aspm_cli.utils.artifact_engine import ArtifactError
        with self.assertRaisesRegex(ArtifactError, "Uploading the results failed"):
            self.run_execute("sca", upload_code=1)
        self.assertTrue(self.out.exists())

    def test_no_report_means_nothing_is_uploaded_and_it_says_why(self):
        from aspm_cli.utils.artifact_engine import ArtifactError
        with self.assertRaisesRegex(ArtifactError, "no vulnerability report"):
            self.run_execute("sca", scan_result=self.result(report=False))
        self.assertEqual(self.uploads, [])
