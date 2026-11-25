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
        s = make_scanner(branch="feature/login", skip_sonar_scan=True)
        self.assertEqual(self.choose(s, ["main", "feature/login"]), "feature/login")

    def test_scan_without_branch_name_ignores_same_named_stale_branch(self):
        """This run's analysis went to main; SonarQube's old 'feature/x' branch must not be picked."""
        s = make_scanner(branch="feature/x")
        self.assertEqual(self.choose(s, ["main", "feature/x"]), "main")
        self.assertTrue(s._use_git_commit)

    def test_scan_uses_branch_reported_by_background_task(self):
        s = make_scanner(branch="main")
        s._task_branch = "feature/x"  # e.g. auto-detected from CI by SonarQube
        self.assertEqual(self.choose(s, ["main", "feature/x"]), "feature/x")
        self.assertTrue(s._use_git_commit)

    def test_unknown_branch_falls_back_to_main_without_git_commit(self):
        s = make_scanner(branch="feature/x", skip_sonar_scan=True)
        self.assertEqual(self.choose(s, ["master", "release"], main="master"), "master")
        self.assertFalse(s._use_git_commit)

    def test_undetected_branch_falls_back_to_main_keeping_git_commit(self):
        s = make_scanner(branch=None)
        self.assertEqual(self.choose(s, ["main", "dev"]), "main")
        self.assertTrue(s._use_git_commit)

    def test_skip_scan_with_undetected_branch_does_not_use_git_commit(self):
        s = make_scanner(branch=None, skip_sonar_scan=True)
        self.assertEqual(self.choose(s, ["main", "dev"]), "main")
        self.assertFalse(s._use_git_commit)

    def test_skip_scan_on_other_branch_does_not_use_git_commit(self):
        s = make_scanner("-Dsonar.branch.name=release", skip_sonar_scan=True, branch="main")
        self.assertEqual(self.choose(s, ["main", "release"]), "release")
        self.assertFalse(s._use_git_commit)

    def test_no_match_and_no_main_raises(self):
        s = make_scanner(branch="feature/x", skip_sonar_scan=True)
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

    def test_branch_given_by_flag_still_sets_upload_branch(self):
        """--branch release in a CI job on main: the upload parameter must say release too."""
        s = make_scanner(skip_sonar_scan=True, branch="release")
        s._chosen_branch, s._use_git_commit = "release", True
        self.process(s, "release")
        self.assertEqual(os.environ.get("ACCUKNOX_BRANCH"), "release")

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
        s = make_scanner(branch="dev", skip_sonar_scan=True)
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
                f.write("ceTaskId=T2\n")
            return 1
        result = self.result_files("main")[0]
        with mock.patch.object(s, "_run_sq_scan", side_effect=scan), \
                mock.patch.object(s, "_sq_get", return_value={"task": {"status": "SUCCESS"}}), \
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
            f.write("ceTaskId=T1\n")
        s._prev_task_id = s._task_id()  # what run() records before starting the scanner
        self.assertFalse(s._fresh_task_file())
        # Not judged by the file's timestamp: a Docker VM clock can be minutes behind the host.
        with open(task, "w") as f:
            f.write("ceTaskId=T2\n")
        old = time.time() - 3600
        os.utime(task, (old, old))
        self.assertTrue(s._fresh_task_file())


class WaitForAnalysisTests(TempDirTest):
    def scanner(self):
        s = make_scanner(f"-Dsonar.projectBaseDir={self.tmp.name.replace(os.sep, '/')}")
        s._poll_seconds = 0
        workdir = os.path.join(self.tmp.name, ".scannerwork")
        os.makedirs(workdir)
        with open(os.path.join(workdir, "report-task.txt"), "w") as f:
            # ceTaskUrl comes from the server's base URL setting and may point anywhere.
            f.write("ceTaskId=T1\nceTaskUrl=http://localhost:9000/api/ce/task?id=T1\n")
        return s

    def test_polls_the_configured_host_not_the_url_in_the_file(self):
        s = self.scanner()
        with mock.patch.object(s, "_sq_get", return_value={"task": {"status": "SUCCESS", "branch": "dev"}}) as get:
            self.assertTrue(s._wait_for_analysis())
        get.assert_called_once_with("https://sonar.example.com/api/ce/task", {"id": "T1"})
        self.assertEqual(s._task_branch, "dev")

    def test_failed_task_returns_code_so_softfail_applies(self):
        s = self.scanner()
        task = os.path.join(self.tmp.name, ".scannerwork", "report-task.txt")

        def scan():
            with open(task, "w") as f:
                f.write("ceTaskId=T2")
            return 0
        with mock.patch.object(s, "_run_sq_scan", side_effect=scan), \
                mock.patch.object(s, "_sq_get", return_value={"task": {"status": "FAILED", "errorMessage": "boom"}}), \
                mock.patch.object(s, "_run_ak_scan") as fetch:
            self.assertEqual(s.run(), (1, None))
        fetch.assert_not_called()

    def test_one_failed_poll_does_not_end_the_wait(self):
        s = self.scanner()
        replies = [TimeoutError("slow"), {"task": {"status": "IN_PROGRESS"}}, {"task": {"status": "SUCCESS"}}]
        with mock.patch.object(s, "_sq_get", side_effect=replies) as get:
            self.assertTrue(s._wait_for_analysis())
        self.assertEqual(get.call_count, 3)

    def test_timeout_does_not_fetch(self):
        s = self.scanner()
        with mock.patch.object(s, "_sq_get", return_value={"task": {"status": "IN_PROGRESS"}}):
            self.assertFalse(s._wait_for_analysis(timeout=0.05))

    def test_unreadable_task_does_not_block_the_fetch(self):
        import urllib.error
        s = self.scanner()
        denied = urllib.error.HTTPError("u", 403, "Forbidden", None, None)
        with mock.patch.object(s, "_sq_get", side_effect=denied) as get:
            self.assertTrue(s._wait_for_analysis())
        self.assertEqual(get.call_count, 1)


class ContainerTaskIdTests(unittest.TestCase):
    def test_task_id_is_read_from_scanner_output(self):
        """The container image keeps report-task.txt inside the container, so there is no file to read."""
        s = make_scanner("-Dsonar.projectBaseDir=/no/such/dir")
        s._poll_seconds = 0
        out = "INFO More about the report processing at https://sonar.example.com/api/ce/task?id=abc-123_X\nANALYSIS SUCCESSFUL"
        with mock.patch("subprocess.run", return_value=mock.Mock(stdout=out, stderr="", returncode=0)), \
                mock.patch("aspm_cli.scan.sq_sast.ToolManager.get_path", return_value="sq"):
            s._run_sq_scan()
        with mock.patch.object(s, "_sq_get", return_value={"task": {"status": "SUCCESS"}}) as get:
            self.assertTrue(s._wait_for_analysis())
        get.assert_called_once_with("https://sonar.example.com/api/ce/task", {"id": "abc-123_X"})


class MacKeychainTests(unittest.TestCase):
    def test_retry_fires_when_the_error_is_on_stdout(self):
        s = make_scanner()
        runs = [mock.Mock(stdout="at nl.altindag.ssl.util.MacCertificateUtils", stderr="", returncode=1),
                mock.Mock(stdout="ANALYSIS SUCCESSFUL", stderr="", returncode=0)]
        with mock.patch("sys.platform", "darwin"), mock.patch("subprocess.run", side_effect=runs) as run, \
                mock.patch("aspm_cli.scan.sq_sast.ToolManager.get_path", return_value="sq"):
            self.assertEqual(s._run_sq_scan(), 0)
        self.assertIn("-Dsonar.scanner.skipSystemTruststore=true", run.call_args_list[1].args[0])


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
