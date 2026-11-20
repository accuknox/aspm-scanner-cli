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


def test_without_local_modelscan_the_model_files_are_scanned_in_the_container(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "model.pkl").write_bytes(b"\x80\x04N.")
    events = []
    monkeypatch.setattr(ml_scan, "docker_pull", lambda image, platform=None: events.append("pull"))
    monkeypatch.setattr(ml_scan.MLScanScanner, "_resolve_local_binary", lambda self: "modelscan")
    monkeypatch.setattr(ml_scan.shutil, "which", lambda name: None)

    class Done:
        returncode, stdout, stderr = 2, "", ""

    commands = []
    monkeypatch.setattr(ml_scan, "run_scan_subprocess", lambda cmd: commands.append(cmd) or Done())
    ml_scan.MLScanScanner("scan -p . -r json", container_mode=False).run()
    assert events == ["pull"]
    assert commands and commands[0][0] == "docker"


def test_without_model_files_local_mode_needs_neither_docker_nor_modelscan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ml_scan, "docker_pull", lambda *a, **k: (_ for _ in ()).throw(AssertionError("pulled")))
    code, _ = ml_scan.MLScanScanner("scan -p . -r json", container_mode=False).run()
    assert code == 0
