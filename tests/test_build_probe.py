import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

from aspm_cli.inference import buildprobe, infer_dependencies


def write(root, rel, text=""):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def by_name(result):
    return {d.name: d for d in result.deps}


def make_system_prefix(tmp):
    """A fake system prefix: zlib header + an OpenSSL config package, like /usr/local."""
    write(tmp, "usr/include/zlib.h", '#define ZLIB_VERSION "1.3.1"\n')
    write(tmp, "usr/lib/cmake/OpenSSL/OpenSSLConfigVersion.cmake", 'set(PACKAGE_VERSION "3.0.13")\n')
    return os.path.join(tmp, "usr")


def cache_text(prefix):
    return (
        "# comment\n//help\n"
        f"ZLIB_INCLUDE_DIR:PATH={prefix}/include\n"
        f"OpenSSL_DIR:PATH={prefix}/lib/cmake/OpenSSL\n"
        "PNG_VERSION_STRING:STRING=1.6.43\n"
        "CMAKE_CXX_COMPILER_VERSION:STRING=15.0.0\n"
        "Missing_DIR:PATH=Missing_DIR-NOTFOUND\n"
    )


class TestCacheReading(unittest.TestCase):
    def test_versions_from_header_config_package_and_version_variable(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = write(tmp, "b/CMakeCache.txt", cache_text(make_system_prefix(tmp)))
            found = buildprobe.versions_from_cache(cache, buildprobe.parse_cmake_cache(cache), "b/CMakeCache.txt")
        self.assertEqual(found["zlib"][0], "1.3.1")
        self.assertEqual(found["openssl"][0], "3.0.13")
        self.assertEqual(found["libpng"][0], "1.6.43")
        self.assertNotIn("cmake", " ".join(found))  # compiler / CMake versions are not libraries
        self.assertNotIn("missing", found)

    def test_switch_off_disables_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "b/CMakeCache.txt", cache_text(make_system_prefix(tmp)))
            with mock.patch.dict(os.environ, {buildprobe.ENV_SWITCH: "off"}):
                self.assertEqual(buildprobe.collect_build_versions(tmp), {})


class TestInferenceUsesBuildVersions(unittest.TestCase):
    def tree(self, tmp):
        """Repo at tmp/repo; the 'installed system' it was built against lives outside it, at tmp/usr."""
        write(tmp, "repo/src/a.c", "#include <zlib.h>\n#include <openssl/ssl.h>\n#include <png.h>\n")
        write(tmp, "repo/build/CMakeCache.txt", cache_text(make_system_prefix(tmp)))
        return os.path.join(tmp, "repo")

    def test_existing_build_dir_fills_versionless_system_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            found = by_name(infer_dependencies(self.tree(tmp)))
        self.assertEqual(found["zlib"].version, "1.3.1")
        self.assertEqual(found["zlib"].purl, "pkg:conan/zlib@1.3.1")
        self.assertEqual(found["zlib"].source, "build-output")
        self.assertTrue(found["zlib"].lookup_eligible)
        self.assertIn("(build-output)", " ".join(found["zlib"].evidence))
        self.assertEqual(found["openssl"].version, "3.0.13")

    def test_a_version_the_repo_states_is_never_overridden(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.tree(tmp)
            write(repo, "CMakeLists.txt", "find_package(ZLIB 1.2.11 EXACT)\n")
            self.assertEqual(by_name(infer_dependencies(repo))["zlib"].version, "1.2.11")

    def test_vendored_trees_do_not_take_the_hosts_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.tree(tmp)
            write(repo, "3rdparty/libwebp/CMakeLists.txt", "")  # versionless vendored copy
            write(repo, "build/CMakeCache.txt", "WebP_VERSION:STRING=1.4.0\n")
            self.assertIsNone(by_name(infer_dependencies(repo))["libwebp"].version)

    def test_switch_off_leaves_versionless(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.tree(tmp)
            with mock.patch.dict(os.environ, {buildprobe.ENV_SWITCH: "off"}):
                self.assertIsNone(by_name(infer_dependencies(repo))["zlib"].version)


class TestConfigureProbe(unittest.TestCase):
    def fake_cmake(self, tmp, prefix):
        bindir = os.path.join(tmp, "bin")
        script = write(
            tmp, "bin/cmake",
            '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = "-B" ] && B="$2"; shift; done\n'
            f'mkdir -p "$B" && cat > "$B/CMakeCache.txt" <<EOF\nZLIB_INCLUDE_DIR:PATH={prefix}/include\nEOF\nexit 1\n',
        )
        os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR)
        return bindir

    def test_no_sandbox_means_the_repos_cmake_is_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "repo/CMakeLists.txt", "project(x)\n")
            marker = os.path.join(tmp, "ran")
            bindir = os.path.join(tmp, "bin")
            script = write(tmp, "bin/cmake", f"#!/bin/sh\ntouch {marker}\n")
            os.chmod(script, 0o755)
            with mock.patch.dict(os.environ, {"PATH": bindir + os.pathsep + os.environ["PATH"]}), \
                    mock.patch.object(buildprobe, "_sandbox_prefix", return_value=None):
                with buildprobe.cmake_configure_cache(os.path.join(tmp, "repo")) as cache:
                    self.assertIsNone(cache)
            self.assertFalse(os.path.exists(marker))

    @unittest.skipIf(os.name == "nt", "the fake cmake is a shell script; the configure probe never runs on Windows (no sandbox)")
    def test_failed_configure_still_yields_what_it_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = make_system_prefix(tmp)
            write(tmp, "repo/CMakeLists.txt", "project(x)\n")
            write(tmp, "repo/src/a.c", "#include <zlib.h>\n")
            bindir = self.fake_cmake(tmp, prefix)
            with mock.patch.dict(os.environ, {"PATH": bindir + os.pathsep + os.environ["PATH"]}), \
                    mock.patch.object(buildprobe, "_sandbox_prefix", return_value=[]):
                found = by_name(infer_dependencies(os.path.join(tmp, "repo")))
            self.assertEqual(found["zlib"].version, "1.3.1")
            self.assertIn("(cmake-configure)", " ".join(found["zlib"].evidence))
            self.assertEqual(sorted(os.listdir(os.path.join(tmp, "repo"))), ["CMakeLists.txt", "src"])  # tree untouched

    @unittest.skipUnless(sys.platform == "darwin", "uses macOS sandbox-exec")
    def test_real_macos_sandbox_denies_network_and_outside_writes(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory(dir=os.path.expanduser("~")) as other:
            prefix = buildprobe._sandbox_prefix(tmp)
            self.assertIsNotNone(prefix)
            inside = os.path.join(os.path.realpath(tmp), "in")
            outside = os.path.join(other, "out")
            subprocess.run([*prefix, "/bin/sh", "-c", f"touch {inside}; touch {outside}"], capture_output=True)
            self.assertTrue(os.path.exists(inside))
            self.assertFalse(os.path.exists(outside))


class TestProbeBudget(unittest.TestCase):
    def test_configure_is_capped_at_a_minute(self):
        self.assertLessEqual(buildprobe.CONFIGURE_TIMEOUT, 60)
