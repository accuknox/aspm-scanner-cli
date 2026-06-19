import subprocess

from aspm_cli.utils.logger import Logger


def _image_exists_locally(image: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def docker_pull(image: str, platform: str = None):
    """Pull a Docker image, or use it if already present locally."""
    if _image_exists_locally(image):
        Logger.get_logger().debug(f"Using local Docker image: {image}")
        return

    Logger.get_logger().debug(f"Pulling Docker image: {image}")
    cmd = ["docker", "pull"]
    if platform:
        cmd.extend(["--platform", platform])
    cmd.append(image)
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        Logger.get_logger().error(f"Failed to pull image {image}")
        Logger.get_logger().error(result.stderr)
        raise RuntimeError(f"Failed to pull image: {image}")

    Logger.get_logger().debug(result.stdout)
    Logger.get_logger().debug(f"Successfully pulled image: {image}")