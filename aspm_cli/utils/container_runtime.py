import os
import shutil
import subprocess

from aspm_cli.utils.logger import Logger

# Priority order: docker first (preserves existing behavior wherever a real
# docker daemon is reachable), then daemonless/containerd-native tools that
# work in EKS/k3s pods without /var/run/docker.sock, DinD, or --privileged.
_RUNTIME_CANDIDATES = ("docker", "nerdctl", "podman")

# docker/nerdctl are daemon clients -- their binary can be on PATH (e.g.
# baked into the scanner image) while no daemon/socket is reachable, which
# is exactly the EKS/containerd failure this module exists to route around.
# podman is daemonless (runs via runc in the pod's own namespace), so it
# needs no such probe.
_DAEMON_PROBE = {
    "docker": ["docker", "info"],
    "nerdctl": ["nerdctl", "info"],
}

_cached_runtime = None


def _is_usable(binary: str) -> bool:
    probe = _DAEMON_PROBE.get(binary)
    if not probe:
        return True
    try:
        return subprocess.run(probe, capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


def get_container_runtime() -> str:
    """
    Resolve the Docker-CLI-compatible binary to use for `run`/`pull`/`image
    inspect` in container-mode scans.

    Override with ACCUKNOX_CONTAINER_RUNTIME. Otherwise picks the first of
    docker, nerdctl, podman that is both on PATH and actually usable --
    docker/nerdctl only count if their daemon responds, so a scanner image
    that merely bundles the docker CLI (no daemon behind it) automatically
    falls through to podman instead of failing at `docker pull`.
    """
    global _cached_runtime
    if _cached_runtime:
        return _cached_runtime

    override = os.getenv("ACCUKNOX_CONTAINER_RUNTIME")
    if override:
        if not shutil.which(override):
            raise RuntimeError(
                f"ACCUKNOX_CONTAINER_RUNTIME={override!r} not found on PATH"
            )
        _cached_runtime = override
        return override

    for candidate in _RUNTIME_CANDIDATES:
        if shutil.which(candidate) and _is_usable(candidate):
            Logger.get_logger().debug(f"Using container runtime: {candidate}")
            _cached_runtime = candidate
            return candidate

    raise RuntimeError(
        "No usable container runtime found (looked for: "
        + ", ".join(_RUNTIME_CANDIDATES)
        + " -- docker/nerdctl need a reachable daemon, podman needs none). "
        "Install podman in the scanner image, or run the scan without --container-mode."
    )


def _reset_cache_for_tests():
    global _cached_runtime
    _cached_runtime = None
