import os
import unittest
from unittest.mock import patch

from aspm_cli.scan.sast import SASTScanner


class IncrementalSastTests(unittest.TestCase):
    def test_targets_are_replaced_by_changed_files(self):
        s = SASTScanner(command="scan -f rules src", container_mode=False, changed_files=["src/a.py", "docs/b.md"])
        with patch("aspm_cli.scan.sast.ToolManager.get_path", return_value="rules"):
            args = s._build_sast_args()
        self.assertEqual(args[-1], "src/a.py")
        self.assertNotIn("docs/b.md", args)
        self.assertNotIn("src", args)

    def test_no_changed_files_skips_scan(self):
        s = SASTScanner(command="scan .", container_mode=False, changed_files=[])
        with patch("aspm_cli.scan.sast.ToolManager.get_path", return_value="rules"), \
                patch("aspm_cli.scan.sast.subprocess.run") as run:
            self.assertEqual(s.run(), (0, None))
        run.assert_not_called()

    def test_resolve_changed_files_falls_back_to_full_scan(self):
        from types import SimpleNamespace
        from aspm_cli.utils.incremental import resolve_changed_files
        self.assertIsNone(resolve_changed_files(SimpleNamespace(changed_only=False)))
        with patch.dict(os.environ, {}, clear=False), patch("aspm_cli.utils.incremental.detect_pr_context", return_value=None):
            self.assertIsNone(resolve_changed_files(SimpleNamespace(changed_only=True, base_ref=None)))


class IncrementalScopeTests(unittest.TestCase):
    def test_trufflehog_filesystem_paths_replaced_flag_values_kept(self):
        from aspm_cli.utils.incremental import scope_trufflehog
        out = scope_trufflehog(["filesystem", "--exclude-paths", "ex.txt", "--only-verified", "."], ["a.py", "b/c.py"], None)
        self.assertEqual(out, ["filesystem", "--exclude-paths", "ex.txt", "--only-verified", "a.py", "b/c.py"])

    def test_trufflehog_git_and_gitleaks_use_commit_range(self):
        from aspm_cli.utils.incremental import scope_trufflehog, scope_gitleaks
        self.assertEqual(scope_trufflehog(["git", "file://."], [], "abc..def")[-2:], ["--since-commit", "abc"])
        self.assertEqual(scope_gitleaks(["detect"], "abc..def")[-1], "--log-opts=abc..def")
        self.assertEqual(scope_gitleaks(["detect", "--no-git"], "abc..def"), ["detect", "--no-git"])

    def test_checkov_dir_becomes_file_list(self):
        from aspm_cli.utils.incremental import scope_checkov
        self.assertEqual(scope_checkov(["-d", "infra", "--framework", "terraform"], ["infra/a.tf", "app/x.py"]),
                         ["--framework", "terraform", "-f", "infra/a.tf"])

    def test_manifest_detection(self):
        from aspm_cli.utils.incremental import touches_manifest
        self.assertTrue(touches_manifest(["src/x.py", "svc/package-lock.json"]))
        self.assertFalse(touches_manifest(["src/x.py", "README.md"]))


class IncrementalResolveTests(unittest.TestCase):
    def _args(self, **kw):
        from types import SimpleNamespace
        return SimpleNamespace(changed_only=True, base_ref=None, **kw)

    def test_ci_base_ref_fallbacks(self):
        from aspm_cli.utils.incremental import _ci_base_ref
        for env, want in (({"CI_MERGE_REQUEST_DIFF_BASE_SHA": "abc"}, "abc"),
                          ({"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main"}, "origin/main"),
                          ({"SYSTEM_PULLREQUEST_TARGETBRANCH": "refs/heads/dev"}, "origin/dev"),
                          ({"BITBUCKET_PR_DESTINATION_BRANCH": "main"}, "origin/main"),
                          ({"ACCUKNOX_BASE_REF": "release"}, "release")):
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(_ci_base_ref(), want)
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(_ci_base_ref())

    def test_over_limit_falls_back_to_full_scan(self):
        from aspm_cli.utils.incremental import resolve_changed_files
        args = self._args()
        args.base_ref = "main"
        with patch.dict(os.environ, {"ACCUKNOX_INCREMENTAL_MAX_FILES": "1"}), \
                patch("aspm_cli.utils.incremental.GitInfo._run_git_command", return_value="x"), \
                patch("aspm_cli.utils.incremental._changed_files", return_value=["a", "b"]), \
                patch("aspm_cli.utils.incremental.os.path.isfile", return_value=True):
            self.assertIsNone(resolve_changed_files(args))

    def test_diff_failure_falls_back_to_full_scan(self):
        from aspm_cli.utils.incremental import resolve_changed_files
        args = self._args()
        args.base_ref = "main"
        with patch("aspm_cli.utils.incremental.GitInfo._run_git_command", return_value=None):
            self.assertIsNone(resolve_changed_files(args))


if __name__ == "__main__":
    unittest.main()
