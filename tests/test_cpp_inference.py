import json
import os
import tempfile
import unittest

from aspm_cli.inference import infer_dependencies
from aspm_cli.inference.base import normalize_dep_name, strip_url_credentials
from aspm_cli.inference.cpp import (
    CppInferrer,
    _load_header_map,
    is_system_header,
    package_for_header,
    sniff_vendored_version,
)
from aspm_cli.inference.overlay import inferred_overlay, render_conan_lock


def write(root, rel, text=""):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def by_name(result):
    return {d.name: d for d in result.deps}


class TestHeaderMap(unittest.TestCase):
    def test_no_header_claimed_by_two_packages(self):
        seen = {}
        for pkg, meta in _load_header_map().items():
            for header in meta["headers"]:
                self.assertNotIn(header, seen, f"{header} in {pkg} and {seen.get(header)}")
                seen[header] = pkg

    def test_every_package_has_conan_name(self):
        for pkg, meta in _load_header_map().items():
            self.assertTrue(meta.get("conan"), pkg)

    def test_lookup(self):
        self.assertEqual(package_for_header("openssl/ssl.h"), "openssl")
        self.assertEqual(package_for_header("zlib.h"), "zlib")
        self.assertIsNone(package_for_header("myproject/zlib.h"))

    def test_system_headers(self):
        for header in ("stdio.h", "vector", "sys/socket.h", "unistd.h", "bits/stdc++.h", "windows.h"):
            self.assertTrue(is_system_header(header), header)
        self.assertFalse(is_system_header("openssl/ssl.h"))
        self.assertFalse(is_system_header("zlib.h"))


class TestIncludeInference(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_system_and_first_party_includes_are_not_dependencies(self):
        write(self.root, "src/main.cpp", '#include <stdio.h>\n#include <vector>\n#include "util/helper.h"\n#include <sys/types.h>\n')
        write(self.root, "src/util/helper.h", "")
        result = CppInferrer().infer(self.root)
        self.assertEqual(result.deps, [])

    def test_known_include_becomes_versionless_flagged_component(self):
        write(self.root, "a.cpp", '#include <openssl/ssl.h>\n#include <zlib.h>\n')
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(set(deps), {"openssl", "zlib"})
        dep = deps["openssl"]
        self.assertIsNone(dep.version)
        self.assertEqual(dep.confidence, "C")
        self.assertFalse(dep.lookup_eligible)
        comp = dep.to_component()
        self.assertNotIn("version", comp)
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["accuknox:inferred"], "source-import")
        self.assertEqual(props["accuknox:confidence"], "C")
        self.assertTrue(props["accuknox:evidence"].startswith("a.cpp:1"))

    def test_commented_out_includes_are_ignored(self):
        write(self.root, "a.cpp", '// #include <zlib.h>\n/* #include <openssl/ssl.h> */\n#if 0\n#include <curl/curl.h>\n#endif\n')
        self.assertEqual(CppInferrer().infer(self.root).deps, [])

    def test_unknown_external_include_is_counted_not_emitted(self):
        write(self.root, "a.cpp", '#include <acme/secret.h>\n')
        result = CppInferrer().infer(self.root)
        self.assertEqual(result.deps, [])
        self.assertEqual(result.unresolved_includes, {"acme/secret.h": 1})

    def test_existing_names_are_skipped(self):
        write(self.root, "a.cpp", '#include <zlib.h>\n#include <openssl/ssl.h>\n')
        result = CppInferrer().infer(self.root, existing_names={"ZLIB"})
        self.assertEqual(set(by_name(result)), {"openssl"})


class TestBuildFileEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_find_package_version_is_a_constraint_not_a_version(self):
        write(self.root, "CMakeLists.txt", "find_package(Boost 1.70 REQUIRED)\nfind_package(ZLIB EXACT 1.2.11)\n")
        deps = by_name(CppInferrer().infer(self.root))
        self.assertIsNone(deps["boost"].version)
        self.assertEqual(deps["boost"].constraint, ">=1.70")
        self.assertFalse(deps["boost"].lookup_eligible)
        self.assertEqual(deps["zlib"].version, "1.2.11")
        self.assertTrue(deps["zlib"].lookup_eligible)

    def test_fetchcontent_known_package_with_release_tag_is_registry_purl(self):
        write(self.root, "CMakeLists.txt",
              "FetchContent_Declare(fmt\n  GIT_REPOSITORY https://github.com/fmtlib/fmt.git\n  GIT_TAG 9.1.0)\n")
        dep = by_name(CppInferrer().infer(self.root))["fmt"]
        self.assertEqual(dep.purl, "pkg:conan/fmt@9.1.0")
        self.assertTrue(dep.lookup_eligible)
        self.assertEqual(dep.confidence, "A")

    def test_fetchcontent_private_git_dep_is_listed_without_lookup_and_without_credentials(self):
        write(self.root, "CMakeLists.txt",
              "FetchContent_Declare(acme_core\n  GIT_REPOSITORY https://user:tok3n@git.acme.corp/platform/core.git\n  GIT_TAG main)\n")
        dep = by_name(CppInferrer().infer(self.root))["acme_core"]
        self.assertFalse(dep.lookup_eligible)
        self.assertEqual(dep.source, "git")
        self.assertNotIn("tok3n", json.dumps(dep.to_component()))
        self.assertNotIn("tok3n", dep.purl)

    def test_github_private_dep_gets_github_purl_at_sha(self):
        sha = "a" * 40
        write(self.root, "CMakeLists.txt",
              f"FetchContent_Declare(core\n  GIT_REPOSITORY git@github.com:Acme/Core.git\n  GIT_TAG {sha})\n")
        dep = by_name(CppInferrer().infer(self.root))["core"]
        self.assertEqual(dep.purl, f"pkg:github/acme/core@{sha}")
        self.assertFalse(dep.lookup_eligible)

    def test_cpm_shorthand(self):
        write(self.root, "CMakeLists.txt", 'CPMAddPackage("gh:gabime/spdlog@1.11.0")\n')
        dep = by_name(CppInferrer().infer(self.root))["spdlog"]
        self.assertEqual(dep.version, "1.11.0")

    def test_vcpkg_overrides_resolve_versions(self):
        write(self.root, "vcpkg.json", json.dumps({
            "dependencies": ["zlib", {"name": "openssl", "version>=": "1.1.1"}],
            "overrides": [{"name": "zlib", "version": "1.2.11"}],
        }))
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(deps["zlib"].version, "1.2.11")
        self.assertIsNone(deps["openssl"].version)
        self.assertEqual(deps["openssl"].constraint, ">=1.1.1")

    def test_bazel_module(self):
        write(self.root, "MODULE.bazel", 'bazel_dep(name = "zlib", version = "1.3")\nbazel_dep(name = "rules_cc", version = "0.0.9")\n')
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(deps["zlib"].version, "1.3")
        self.assertNotIn("rules_cc", deps)

    def test_meson_wrap(self):
        write(self.root, "subprojects/zlib.wrap", "[wrap-file]\ndirectory = zlib-1.2.11\nsource_url = https://zlib.net/zlib-1.2.11.tar.gz\n")
        self.assertEqual(by_name(CppInferrer().infer(self.root))["zlib"].version, "1.2.11")


class TestVendoredAndSubmodules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_vendored_known_package_version_from_header_macro(self):
        write(self.root, "third_party/zlib/zlib.h", '#define ZLIB_VERSION "1.2.11"\n')
        write(self.root, "src/a.cpp", '#include <zlib.h>\n')
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(deps["zlib"].version, "1.2.11")
        self.assertEqual(deps["zlib"].confidence, "B")
        self.assertEqual(deps["zlib"].source, "vendored")
        self.assertTrue(deps["zlib"].lookup_eligible)

    def test_vendored_unknown_dir_is_listed_without_lookup(self):
        write(self.root, "third_party/acme_codec/VERSION", "2.4.1\n")
        write(self.root, "third_party/acme_codec/codec.h", "")
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(deps["acme_codec"].version, "2.4.1")
        self.assertFalse(deps["acme_codec"].lookup_eligible)

    def test_vendored_versionless_dir_is_c(self):
        write(self.root, "vendor/mystery/m.c", "")
        dep = by_name(CppInferrer().infer(self.root))["mystery"]
        self.assertIsNone(dep.version)
        self.assertEqual(dep.confidence, "C")

    def test_includes_inside_vendored_trees_are_not_ours(self):
        write(self.root, "third_party/foo/foo.c", '#include <openssl/ssl.h>\n')
        self.assertNotIn("openssl", by_name(CppInferrer().infer(self.root)))

    def test_gitmodules_private_submodule(self):
        write(self.root, ".gitmodules",
              '[submodule "libs/core"]\n\tpath = libs/core\n\turl = https://token@git.acme.corp/x/core.git\n')
        dep = by_name(CppInferrer().infer(self.root))["core"]
        self.assertEqual(dep.source, "git")
        self.assertFalse(dep.lookup_eligible)
        self.assertEqual(dep.kind, "submodule")
        self.assertNotIn("token@", json.dumps(dep.to_component()))

    def test_sniff_project_version_in_cmake(self):
        write(self.root, "lib/CMakeLists.txt", "project(lib VERSION 3.2.1 LANGUAGES C)\n")
        self.assertEqual(sniff_vendored_version(os.path.join(self.root, "lib"), "lib"), "3.2.1")


class TestOverlayAndSafety(unittest.TestCase):
    def test_overlay_contains_only_resolved_registry_deps_and_is_removed(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "CMakeLists.txt", "find_package(ZLIB EXACT 1.2.11)\nfind_package(OpenSSL 1.1)\n")
            deps = CppInferrer().infer(root).deps
            before = sorted(os.listdir(root))
            with inferred_overlay(deps) as overlay:
                self.assertTrue(overlay and not overlay.startswith(root))
                lock = json.load(open(os.path.join(overlay, "conan.lock")))
                self.assertEqual(lock["requires"], ["zlib/1.2.11"])
            self.assertFalse(os.path.exists(overlay))
            self.assertEqual(sorted(os.listdir(root)), before)

    def test_overlay_is_none_without_eligible_deps(self):
        with inferred_overlay([]) as overlay:
            self.assertIsNone(overlay)

    def test_inference_never_writes_into_tree(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "a.cpp", "#include <zlib.h>\n")
            snapshot = sorted(os.listdir(root))
            infer_dependencies(root)
            self.assertEqual(sorted(os.listdir(root)), snapshot)

    def test_helpers(self):
        self.assertEqual(strip_url_credentials("https://u:p@h.com/x.git"), "https://h.com/x.git")
        self.assertEqual(normalize_dep_name("acme/Boost"), "boost")
        self.assertEqual(normalize_dep_name("nlohmann_json"), normalize_dep_name("nlohmann-json"))
        self.assertIn("zlib/1.2.11", render_conan_lock(CppInferrer().infer(self._zlib_tree()).deps))

    def _zlib_tree(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        write(self._tmp.name, "CMakeLists.txt", "find_package(ZLIB EXACT 1.2.11)\n")
        return self._tmp.name


if __name__ == "__main__":
    unittest.main()


class TestVendoredHeaderNames(unittest.TestCase):
    def test_openssl_style_version_header(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "third_party/openssl/include/openssl/opensslv.h",
                  '# define OPENSSL_VERSION_NUMBER 0x1010111fL\n# define OPENSSL_VERSION_TEXT "OpenSSL 1.1.1k  25 Mar 2021"\n')
            dep = by_name(CppInferrer().infer(root))["openssl"]
            self.assertEqual(dep.version, "1.1.1k")
            self.assertEqual(dep.purl, "pkg:conan/openssl@1.1.1k")


class TestMoreBuildSystems(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_bazel_workspace_http_archive_and_git_repository(self):
        write(self.root, "WORKSPACE", '''
http_archive(
    name = "zlib",
    urls = ["https://zlib.net/zlib-1.2.11.tar.gz"],
    strip_prefix = "zlib-1.2.11",
)
http_archive(name = "acme_codec", urls = ["https://user:pw@git.acme.corp/codec-3.1.0.tar.gz"])
git_repository(name = "acme_core", remote = "https://git.acme.corp/core.git", commit = "%s")
''' % ("b" * 40))
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(deps["zlib"].purl, "pkg:conan/zlib@1.2.11")
        self.assertTrue(deps["zlib"].lookup_eligible)
        self.assertEqual(deps["acme_codec"].version, "3.1.0")
        self.assertFalse(deps["acme_codec"].lookup_eligible)
        self.assertNotIn("pw@", json.dumps(deps["acme_codec"].to_component()))
        self.assertFalse(deps["acme_core"].lookup_eligible)
        self.assertEqual(deps["acme_core"].version, "b" * 40)

    def test_meson_dependency_is_constraint_only_and_ignores_unknown(self):
        write(self.root, "meson.build", "zlib = dependency('zlib', version: '>=1.2')\nx = dependency('totally-unknown')\n")
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(set(deps), {"zlib"})
        self.assertIsNone(deps["zlib"].version)
        self.assertEqual(deps["zlib"].constraint, ">=1.2")

    def test_autotools_exact_resolves_range_does_not(self):
        write(self.root, "configure.ac", "PKG_CHECK_MODULES([ZLIB], [zlib = 1.2.11])\nPKG_CHECK_MODULES([SSL], [openssl >= 1.1.0])\n")
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(deps["zlib"].version, "1.2.11")
        self.assertIsNone(deps["openssl"].version)
        self.assertEqual(deps["openssl"].constraint, ">=1.1.0")


class TestRealRepoRegressions(unittest.TestCase):
    """Found by scanning nothings/stb and mackron/miniaudio."""

    def test_relative_includes_are_first_party(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "miniaudio.c", "")
            write(root, "examples/a.c", '#include "../miniaudio.c"\n#include "./b.h"\n')
            write(root, "examples/b.h", "")
            result = CppInferrer().infer(root)
            self.assertEqual(result.deps, [])
            self.assertEqual(result.unresolved_includes, {})

    def test_header_matching_is_case_insensitive_and_supports_prefix_globs(self):
        self.assertEqual(package_for_header("sdl.h"), "sdl")
        self.assertEqual(package_for_header("SDL_opengl.h"), "sdl")
        self.assertEqual(package_for_header("SDL/SDL.h"), "sdl")
        self.assertEqual(package_for_header("vorbis/vorbisfile.h"), "libvorbis")

    def test_platform_headers_are_not_dependencies(self):
        for header in ("emscripten.h", "jni.h", "dos.h", "intrin.h", "gl/gl.h", "GL/glu.h", "alsa/asoundlib.h"):
            self.assertTrue(is_system_header(header), header)

    def test_header_map_prefix_globs_do_not_collide(self):
        from aspm_cli.inference.cpp import _header_index
        _exact, prefixes = _header_index()
        keys = [k for k, _ in prefixes]
        self.assertEqual(len(keys), len(set(keys)))


class TestDockerfileAndCiEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_dockerfile_apt_install_is_constraint_only(self):
        write(self.root, "Dockerfile", "FROM ubuntu:22.04\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends \\\n"
                                      "    build-essential cmake libssl-dev=3.0.2-0ubuntu1.15 libboost-all-dev zlib1g-dev:amd64 ninja-build\n")
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(set(deps), {"openssl", "boost", "zlib"})
        for dep in deps.values():
            self.assertIsNone(dep.version)  # a distro version is a patched build, not an upstream version
            self.assertFalse(dep.lookup_eligible)
            self.assertEqual(dep.kind, "ci-config")
        self.assertEqual(deps["openssl"].constraint, "apt-get=3.0.2-0ubuntu1.15")
        self.assertTrue(deps["openssl"].evidence[0].startswith("Dockerfile:"))

    def test_github_workflow_conan_ref_resolves_version(self):
        write(self.root, ".github/workflows/ci.yml",
              "jobs:\n  b:\n    steps:\n      - run: conan install zlib/1.2.11@ --build=missing\n"
              "      - run: conan install --requires=fmt/9.1.0 --build=missing\n"
              "      - run: sudo apt install libcurl4-openssl-dev\n      - run: brew install sdl2\n"
              "      - run: vcpkg install openssl:x64-linux\n")
        deps = by_name(CppInferrer().infer(self.root))
        self.assertEqual(deps["zlib"].version, "1.2.11")
        self.assertTrue(deps["zlib"].lookup_eligible)
        self.assertEqual(deps["fmt"].version, "9.1.0")
        self.assertEqual({"libcurl", "sdl", "openssl"} - set(deps), set())
        self.assertFalse(deps["libcurl"].lookup_eligible)

    def test_unrelated_install_lines_are_ignored(self):
        write(self.root, "Dockerfile", "RUN apt-get install -y curl git openssl ca-certificates python3-pip\nRUN pip install conan\n")
        write(self.root, ".github/workflows/x.yml", "steps:\n  - run: brew install curl openssl@3\n")
        self.assertEqual(set(by_name(CppInferrer().infer(self.root))), {"openssl"})  # only brew's openssl@3


class TestLargeRepoRegressions(unittest.TestCase):
    """Found by scanning ClickHouse and dolphin."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_cmake_wrapper_is_folded_into_its_submodule_without_its_own_version(self):
        write(self.root, ".gitmodules", '[submodule "contrib/zlib-ng"]\n\tpath = contrib/zlib-ng\n\turl = https://github.com/zlib-ng/zlib-ng\n')
        write(self.root, "contrib/zlib-ng-cmake/CMakeLists.txt", "project(glue VERSION 200.0.0)\n")
        os.makedirs(os.path.join(self.root, "contrib/zlib-ng"))
        deps = CppInferrer().infer(self.root).deps
        self.assertEqual([d.name for d in deps], ["zlib-ng"])
        self.assertEqual(deps[0].kind, "submodule")
        self.assertIn("contrib/zlib-ng-cmake/", deps[0].evidence)

    def test_cmake_wrapper_without_submodule_keeps_no_version(self):
        write(self.root, "contrib/foo-cmake/CMakeLists.txt", "project(glue VERSION 9.9.9)\n")
        dep = by_name(CppInferrer().infer(self.root))["foo"]
        self.assertIsNone(dep.version)

    def test_generic_and_nested_directories_are_not_dependencies(self):
        write(self.root, "Externals/discord-rpc/thirdparty/include/rapidjson/a.h", "")
        write(self.root, "Externals/mbedtls/3rdparty/everest/x.c", "")
        write(self.root, "Externals/mbedtls/CMakeLists.txt", "find_package(ZLIB)\n")
        names = set(by_name(CppInferrer().infer(self.root)))
        self.assertEqual(names, {"discord-rpc", "mbedtls"})  # not include / everest / zlib

    def test_build_files_and_includes_inside_a_submodule_are_not_ours(self):
        write(self.root, ".gitmodules", '[submodule "libs/core"]\n\tpath = libs/core\n\turl = https://git.acme.corp/core.git\n')
        write(self.root, "libs/core/CMakeLists.txt", "find_package(ZLIB EXACT 1.2.11)\n")
        write(self.root, "libs/core/core.c", "#include <openssl/ssl.h>\n")
        self.assertEqual(set(by_name(CppInferrer().infer(self.root))), {"core"})

    def test_externals_directory_is_a_vendor_directory(self):
        write(self.root, "Externals/zlib/zlib.h", '#define ZLIB_VERSION "1.2.11"\n')
        dep = by_name(CppInferrer().infer(self.root))["zlib"]
        self.assertEqual((dep.version, dep.confidence), ("1.2.11", "B"))
