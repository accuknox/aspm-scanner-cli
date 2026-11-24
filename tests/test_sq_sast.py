import json
import os
import tempfile
import time
import unittest
from unittest import mock

from aspm_cli.scan.sq_sast import SQSASTScanner

GIT_SHA = "a" * 40
SONAR_SHA = "b" * 40


def make_scanner(command="", skip_sonar_scan=False, branch="main", commit_sha=GIT_SHA, repo_url=None):
    base = "-Dsonar.projectKey=proj -Dsonar.token=tok -Dsonar.host.url=https://sonar.example.com/"
    return SQSASTScanner(skip_sonar_scan, f"{base} {command}".strip(), repo_url=repo_url,
                         branch=branch, commit_sha=commit_sha)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for key in ("ACCUKNOX_BRANCH", "ACCUKNOX_COMMIT_SHA"):
            os.environ.pop(key, None)

    def result_files(self, *branches):
        paths = []
        for i, branch in enumerate(branches):
            path = os.path.join(self.tmp.name, f"SQ-proj-{i}.json")
            with open(path, "w") as f:
                json.dump({"branch": branch, "issues": [], "hotspots": []}, f)
            paths.append(path)
        return paths


class HostUrlTests(unittest.TestCase):
    def test_trailing_slash_is_stripped(self):
        self.assertEqual(make_scanner().sonar_host_url, "https://sonar.example.com")

    def test_missing_host_stays_none(self):
        self.assertIsNone(SQSASTScanner(False, "-Dsonar.projectKey=p").sonar_host_url)


class BranchSelectionTests(TempDirTest):
    def choose(self, scanner, branches, main="main"):
        files = self.result_files(*branches)
        with mock.patch.object(scanner, "_main_branch", return_value=main):
            chosen = scanner._choose_branch_file(files)
        with open(chosen) as f:
            return json.load(f)["branch"]

    def test_sonar_branch_name_wins_over_git_branch(self):
        s = make_scanner("-Dsonar.branch.name=release/2.0", branch="main")
        self.assertEqual(self.choose(s, ["main", "release/2.0"]), "release/2.0")
        self.assertEqual(s._chosen_branch, "release/2.0")
        self.assertTrue(s._use_git_commit)  # this run analysed the checkout into release/2.0

    def test_git_branch_with_slash_matches_file_content(self):
        s = make_scanner(branch="feature/login")
        self.assertEqual(self.choose(s, ["main", "feature/login"]), "feature/login")

    def test_unknown_branch_falls_back_to_main_without_git_commit(self):
        s = make_scanner(branch="feature/x")
        self.assertEqual(self.choose(s, ["master", "release"], main="master"), "master")
        self.assertFalse(s._use_git_commit)

    def test_undetected_branch_falls_back_to_main_keeping_git_commit(self):
        s = make_scanner(branch=None)
        self.assertEqual(self.choose(s, ["main", "dev"]), "main")
        self.assertTrue(s._use_git_commit)

    def test_skip_scan_on_other_branch_does_not_use_git_commit(self):
        s = make_scanner("-Dsonar.branch.name=release", skip_sonar_scan=True, branch="main")
        self.assertEqual(self.choose(s, ["main", "release"]), "release")
        self.assertFalse(s._use_git_commit)

    def test_no_match_and_no_main_raises(self):
        s = make_scanner(branch="feature/x")
        with self.assertRaises(RuntimeError):
            self.choose(s, ["a", "b"], main=None)


class LabelTests(TempDirTest):
    def process(self, scanner, branch_in_file):
        path = self.result_files(branch_in_file)[0]
        with mock.patch.object(scanner, "_analysis_revision", return_value=SONAR_SHA):
            scanner._process_result_file(path)
        with open(path) as f:
            return json.load(f)["repo_details"]

    def test_chosen_branch_labels_the_upload(self):
        s = make_scanner("-Dsonar.branch.name=release/2.0", branch="main")
        s._chosen_branch, s._use_git_commit = "release/2.0", True
        details = self.process(s, "release/2.0")
        self.assertEqual(details["branch"], "release/2.0")
        self.assertEqual(details["commit"], GIT_SHA)
        # Upload query parameters follow the data, not git.
        self.assertEqual(os.environ.get("ACCUKNOX_BRANCH"), "release/2.0")

    def test_main_fallback_uses_sonar_revision(self):
        s = make_scanner(branch="feature/x")
        s._chosen_branch, s._use_git_commit = "main", False
        details = self.process(s, "main")
        self.assertEqual(details["branch"], "main")
        self.assertEqual(details["commit"], SONAR_SHA)
        self.assertEqual(os.environ.get("ACCUKNOX_COMMIT_SHA"), SONAR_SHA)

    def test_user_identity_overrides_are_kept(self):
        os.environ["ACCUKNOX_BRANCH"] = "mine"
        s = make_scanner(branch="feature/x")
        s._chosen_branch, s._use_git_commit = "main", False
        self.process(s, "main")
        self.assertEqual(os.environ["ACCUKNOX_BRANCH"], "mine")

    def test_single_result_keeps_git_values(self):
        s = make_scanner(branch="feature/x")
        details = self.process(s, "main")
        self.assertEqual(details["branch"], "feature/x")
        self.assertEqual(details["commit"], GIT_SHA)
        self.assertNotIn("ACCUKNOX_BRANCH", os.environ)


class FetchCleanupTests(TempDirTest):
    def test_unchosen_branch_files_are_removed(self):
        files = self.result_files("main", "dev", "release")
        s = make_scanner(branch="dev")
        fetcher = mock.MagicMock()

        async def fetch_all():
            return files
        fetcher.return_value.fetch_all = fetch_all
        with mock.patch("accuknox_sq_sast.sonarqube_fetcher.SonarQubeFetcher", fetcher):
            chosen = s._run_ak_scan()
        self.assertEqual(chosen, files[1])
        self.assertEqual([os.path.exists(p) for p in files], [False, True, False])


class ScannerFailureTests(TempDirTest):
    def test_failed_scan_returns_code_without_fetching(self):
        s = make_scanner(f"-Dsonar.projectBaseDir={self.tmp.name.replace(os.sep, '/')}")
        with mock.patch.object(s, "_run_sq_scan", return_value=3), \
                mock.patch.object(s, "_run_ak_scan") as fetch:
            self.assertEqual(s.run(), (3, None))  # caller applies --softfail
        fetch.assert_not_called()

    def test_gate_failure_after_quiet_analysis_still_uploads(self):
        """No 'ANALYSIS SUCCESSFUL' in the log (log level WARN), but this scan wrote report-task.txt."""
        s = make_scanner(f"-Dsonar.projectBaseDir={self.tmp.name.replace(os.sep, '/')}")
        workdir = os.path.join(self.tmp.name, ".scannerwork")
        os.makedirs(workdir)

        def scan():
            with open(os.path.join(workdir, "report-task.txt"), "w") as f:
                f.write("ceTaskUrl=\n")
            return 1
        result = self.result_files("main")[0]
        with mock.patch.object(s, "_run_sq_scan", side_effect=scan), \
                mock.patch.object(s, "_run_ak_scan", return_value=result), \
                mock.patch.object(s, "_analysis_revision", return_value=None):
            code, path = s.run()
        self.assertEqual((code, path), (1, result))

    def test_stale_task_file_does_not_count_as_this_analysis(self):
        s = make_scanner(f"-Dsonar.projectBaseDir={self.tmp.name.replace(os.sep, '/')}")
        workdir = os.path.join(self.tmp.name, ".scannerwork")
        os.makedirs(workdir)
        task = os.path.join(workdir, "report-task.txt")
        with open(task, "w") as f:
            f.write("ceTaskUrl=\n")
        old = time.time() - 3600
        os.utime(task, (old, old))
        s._scan_started = time.time()
        self.assertFalse(s._fresh_task_file())


class SonarApiTests(unittest.TestCase):
    def test_requests_use_system_and_certifi_trust(self):
        s = make_scanner()
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"branches": [{"name": "trunk", "isMain": true}]}'
        with mock.patch("urllib.request.urlopen", return_value=response) as urlopen, \
                mock.patch("aspm_cli.scan.sq_sast.download_context", return_value="CTX"):
            self.assertEqual(s._main_branch(), "trunk")
        request = urlopen.call_args[0][0]
        self.assertEqual(urlopen.call_args.kwargs["context"], "CTX")
        self.assertTrue(request.full_url.startswith("https://sonar.example.com/api/project_branches/list?"))
        self.assertTrue(request.get_header("Authorization").startswith("Basic "))


if __name__ == "__main__":
    unittest.main()
