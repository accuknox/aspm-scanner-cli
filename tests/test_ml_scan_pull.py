from aspm_cli.scan import ml_scan


def test_no_model_files_means_no_image_pull(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("print('hi')\n")
    pulls = []
    monkeypatch.setattr(ml_scan, "docker_pull", lambda image, platform=None: pulls.append(image))
    code, result_file = ml_scan.MLScanScanner("scan -p . -r json", container_mode=True).run()
    assert code == 0 and result_file == "results.json"
    assert pulls == []


def test_model_files_pull_the_image_before_scanning(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "model.pkl").write_bytes(b"\x80\x04N.")
    events = []
    monkeypatch.setattr(ml_scan, "docker_pull", lambda image, platform=None: events.append("pull"))

    class Done:
        returncode, stdout, stderr = 2, "", ""

    def fake_run(cmd):
        events.append("scan")
        return Done()

    monkeypatch.setattr(ml_scan, "run_scan_subprocess", fake_run)
    ml_scan.MLScanScanner("scan -p . -r json", container_mode=True).run()
    assert events[:2] == ["pull", "scan"]
