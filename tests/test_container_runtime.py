import os
import subprocess

import pytest

import sys

from aspm_cli.utils import container_runtime
import aspm_cli.utils.docker_pull  # noqa: F401 - ensures the real submodule is in sys.modules
from aspm_cli.scan.sast import SASTScanner

docker_pull_module = sys.modules["aspm_cli.utils.docker_pull"]


@pytest.fixture(autouse=True)
def _reset_runtime_cache(monkeypatch):
    container_runtime._reset_cache_for_tests()
    monkeypatch.delenv("ACCUKNOX_CONTAINER_RUNTIME", raising=False)
    yield
    container_runtime._reset_cache_for_tests()


def test_prefers_docker_when_daemon_reachable(monkeypatch):
    monkeypatch.setattr(
        container_runtime.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "docker" else None
    )
    monkeypatch.setattr(container_runtime, "_is_usable", lambda name: True)
    assert container_runtime.get_container_runtime() == "docker"


def test_falls_back_to_nerdctl_without_docker(monkeypatch):
    monkeypatch.setattr(
        container_runtime.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "nerdctl" else None
    )
    monkeypatch.setattr(container_runtime, "_is_usable", lambda name: True)
    assert container_runtime.get_container_runtime() == "nerdctl"


def test_falls_back_to_podman_without_docker_or_nerdctl(monkeypatch):
    monkeypatch.setattr(
        container_runtime.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "podman" else None
    )
    assert container_runtime.get_container_runtime() == "podman"


def test_raises_when_no_runtime_found(monkeypatch):
    monkeypatch.setattr(container_runtime.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="No usable container runtime found"):
        container_runtime.get_container_runtime()


def test_docker_binary_present_but_daemon_unreachable_falls_back_to_podman(monkeypatch):
    """Reproduces the EKS failure: scanner image bundles the docker CLI but
    there is no dockerd behind /var/run/docker.sock. `docker` must not win
    just because the binary exists on PATH."""
    monkeypatch.setattr(
        container_runtime.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in ("docker", "podman") else None,
    )

    def fake_run(cmd, **kwargs):
        if cmd[0] == "docker":
            raise FileNotFoundError("dial unix /var/run/docker.sock: no such file or directory")
        raise AssertionError(f"unexpected probe: {cmd}")

    monkeypatch.setattr(container_runtime.subprocess, "run", fake_run)
    assert container_runtime.get_container_runtime() == "podman"


def test_env_override_wins(monkeypatch):
    monkeypatch.setenv("ACCUKNOX_CONTAINER_RUNTIME", "podman")
    monkeypatch.setattr(
        container_runtime.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "podman" else None
    )
    assert container_runtime.get_container_runtime() == "podman"


def test_env_override_missing_binary_raises(monkeypatch):
    monkeypatch.setenv("ACCUKNOX_CONTAINER_RUNTIME", "nerdctl")
    monkeypatch.setattr(container_runtime.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="ACCUKNOX_CONTAINER_RUNTIME"):
        container_runtime.get_container_runtime()


def test_result_cached_across_calls(monkeypatch):
    calls = []

    def fake_which(name):
        calls.append(name)
        return "/usr/bin/nerdctl" if name == "nerdctl" else None

    monkeypatch.setattr(container_runtime.shutil, "which", fake_which)
    monkeypatch.setattr(container_runtime, "_is_usable", lambda name: True)
    container_runtime.get_container_runtime()
    container_runtime.get_container_runtime()
    # docker (miss) + nerdctl (hit) probed once; second call served from cache
    assert calls == ["docker", "nerdctl"]


def test_docker_pull_uses_resolved_runtime(monkeypatch):
    monkeypatch.setattr(container_runtime, "_cached_runtime", "nerdctl")
    seen_cmds = []

    def fake_run(cmd, **kwargs):
        seen_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    docker_pull_module.docker_pull("some/image:tag")

    assert seen_cmds[0][0] == "nerdctl"
    assert seen_cmds[0][1:3] == ["image", "inspect"]


def test_sast_container_mode_command_uses_resolved_runtime(monkeypatch):
    monkeypatch.setattr(container_runtime, "_cached_runtime", "podman")
    scanner = SASTScanner(command="scan .", container_mode=True)
    cmd = scanner._build_sast_command(["scan", "--json"])
    assert cmd[0] == "podman"
    assert "run" in cmd


def test_sast_non_container_mode_unaffected(monkeypatch):
    monkeypatch.setattr(
        "aspm_cli.scan.sast.ToolManager.get_path", lambda name: "/opt/opengrep/opengrep"
    )
    scanner = SASTScanner(command="scan .", container_mode=False)
    cmd = scanner._build_sast_command(["scan", "--json"])
    assert cmd[0] == "/opt/opengrep/opengrep"
