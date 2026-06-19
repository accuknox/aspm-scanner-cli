import json
import os
import shlex
import subprocess
import uuid

from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils import config, docker_pull
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.ml_scan import (
    build_model_path,
    build_ondemand_modelscan_payload,
    count_issues,
    derive_model_metadata,
    discover_model_files,
    load_modelscan_output,
    merge_modelscan_result,
    normalize_modelscan_cli_args,
    parse_scan_path_from_command,
)
from aspm_cli.utils.path_safety import resolve_path_within_root
from aspm_cli.utils.subprocess_utils import run_scan_subprocess
from colorama import Fore

DEFAULT_ML_SCAN_IMAGE = (
    "public.ecr.aws/k9v9d5v2/accuknox/ondemand_modelscan:1.0.21"
)
DEFAULT_ML_SCAN_MODULE = "ondemand_modelscan"
DEFAULT_ML_SCAN_TAG = "1.0.21"
DEFAULT_ML_SCAN_PLATFORM = "linux/amd64"


def default_ml_scan_image() -> str:
    """Resolve ondemand_modelscan image (public ECR by default; on-prem via IMAGE_REGISTRY)."""
    if os.getenv("ML_SCAN_IMAGE"):
        return os.getenv("ML_SCAN_IMAGE", "")
    registry = os.getenv("ML_SCAN_IMAGE_REGISTRY") or os.getenv("IMAGE_REGISTRY")
    if registry:
        tag = os.getenv("ML_SCAN_IMAGE_TAG", DEFAULT_ML_SCAN_TAG)
        module = os.getenv("ML_SCAN_IMAGE_MODULE", DEFAULT_ML_SCAN_MODULE)
        return f"{registry.rstrip('/')}/{module}:{tag}"
    return DEFAULT_ML_SCAN_IMAGE


def default_ml_scan_docker_platform() -> str:
    return os.getenv(
        "ML_SCAN_DOCKER_PLATFORM",
        os.getenv("DOCKER_DEFAULT_PLATFORM", DEFAULT_ML_SCAN_PLATFORM),
    )


WORK_DIR = "/workdir"
TEMP_SCAN_DIR = ".accuknox-modelscan"


class MLScanScanner:
    result_file = "results.json"

    def __init__(
        self,
        command,
        container_mode=False,
        repo_url=None,
        commit_ref=None,
        model_name=None,
        source_type="github",
    ):
        self.command = command
        self.container_mode = container_mode
        self.scan_image = os.getenv("SCAN_IMAGE", default_ml_scan_image())
        self.repo_url = repo_url
        self.commit_ref = commit_ref
        self.model_name = model_name
        self.source_type = source_type or "github"
        self.cwd = os.getcwd()

    def run(self):
        temp_files = []
        try:
            if self.container_mode:
                docker_pull(
                    self.scan_image,
                    platform=default_ml_scan_docker_platform(),
                )

            if "--help" in (self.command or ""):
                cmd = self._build_scan_command(["scan", "--help"], ".")
                result = run_scan_subprocess(cmd)
                Logger.log_with_color("INFO", result.stdout or result.stderr, Fore.WHITE)
                return config.PASS_RETURN_CODE, None

            scan_root = parse_scan_path_from_command(self.command)
            try:
                resolve_path_within_root(scan_root, self.cwd)
            except ValueError as exc:
                Logger.get_logger().error(str(exc))
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

            model_files = discover_model_files(scan_root, cwd=self.cwd)

            if not model_files:
                Logger.get_logger().info(
                    "No model files found to scan. "
                    f"Looked under '{scan_root}' for extensions: .pkl, .pt, .pth, .h5, .keras, .pb, .ckpt, .npy"
                )
                self._write_payload([], scan_root)
                return config.PASS_RETURN_CODE, self.result_file

            metadata = derive_model_metadata(
                self.repo_url,
                self.commit_ref,
                model_name=self.model_name,
                source_type=self.source_type,
            )
            os.makedirs(TEMP_SCAN_DIR, exist_ok=True)

            modelscan_results = []
            scan_failures = 0

            for index, model_file in enumerate(model_files, start=1):
                rel_model_file = os.path.relpath(model_file, self.cwd)
                Logger.get_logger().info(
                    f"Scanning model file {index}/{len(model_files)}: {rel_model_file}"
                )
                temp_output = os.path.join(
                    TEMP_SCAN_DIR,
                    f"{uuid.uuid4().hex}.json",
                )
                temp_files.append(temp_output)
                scan_args = normalize_modelscan_cli_args(
                    f"scan -p {shlex.quote(rel_model_file)} -r json",
                    temp_output,
                )
                cmd = self._build_scan_command(scan_args, rel_model_file)

                Logger.get_logger().debug(f"Running ML scan: {' '.join(cmd)}")
                result = run_scan_subprocess(cmd)

                if result.stdout:
                    Logger.get_logger().debug(
                        result.stdout.replace("modelscan", "[scanner]")
                    )
                if result.stderr:
                    Logger.get_logger().error(
                        result.stderr.replace("modelscan", "[scanner]")
                    )

                # ModelScan exits 0 (clean) or 1 (issues found), same as Checkov/Trivy.
                # Other codes are runtime errors even if a partial output file exists.
                if not os.path.exists(temp_output):
                    scan_failures += 1
                    Logger.get_logger().error(
                        f"ModelScan failed for {rel_model_file} "
                        f"(exit {result.returncode}, no output file)"
                    )
                    continue

                if result.returncode not in (0, 1):
                    scan_failures += 1
                    Logger.get_logger().error(
                        f"ModelScan failed for {rel_model_file} (exit {result.returncode})"
                    )
                    continue

                raw = load_modelscan_output(temp_output)
                model_path = build_model_path(
                    metadata["model_id"],
                    metadata["commit_ref"],
                    model_file,
                    scan_root,
                    cwd=self.cwd,
                )
                modelscan_results.append(merge_modelscan_result(raw, model_path))

            self._write_payload(modelscan_results, scan_root, metadata)

            if scan_failures and not modelscan_results:
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

            issue_count = count_issues(modelscan_results)
            if issue_count > 0:
                Logger.get_logger().error(
                    f"ModelScan found {issue_count} issue(s) across {len(modelscan_results)} model file(s)."
                )
                return 1, self.result_file

            Logger.get_logger().info(
                f"ModelScan completed for {len(modelscan_results)} model file(s) with no issues."
            )
            return 0, self.result_file
        except subprocess.TimeoutExpired:
            Logger.get_logger().error("ML scan timed out")
            return config.SOMETHING_WENT_WRONG_RETURN_CODE, None
        except subprocess.CalledProcessError as e:
            Logger.get_logger().error(f"Error during ML scan: {e}")
            raise
        finally:
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except OSError:
                    pass

    def _write_payload(self, modelscan_results, scan_root, metadata=None):
        metadata = metadata or derive_model_metadata(
            self.repo_url,
            self.commit_ref,
            model_name=self.model_name,
            source_type=self.source_type,
        )
        payload = build_ondemand_modelscan_payload(modelscan_results, metadata)
        with open(self.result_file, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def _resolve_local_binary(self) -> str:
        try:
            return ToolManager.get_path("ml-scan")
        except (ValueError, FileNotFoundError):
            return "modelscan"

    def _docker_path(self, host_path: str) -> str:
        if os.path.isabs(host_path):
            return os.path.join(WORK_DIR, os.path.relpath(host_path, self.cwd))
        return os.path.join(WORK_DIR, host_path)

    def _build_scan_command(self, args, rel_model_path: str):
        if not self.container_mode:
            return [self._resolve_local_binary(), *args]

        docker_args = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-p", "--path") and i + 1 < len(args):
                docker_args.extend([arg, self._docker_path(args[i + 1])])
                i += 2
                continue
            if arg in ("-o", "--output") and i + 1 < len(args):
                docker_args.extend([arg, self._docker_path(args[i + 1])])
                i += 2
                continue
            docker_args.append(arg)
            i += 1

        cmd = ["docker", "run", "--rm"]
        platform = default_ml_scan_docker_platform()
        if platform:
            cmd.extend(["--platform", platform])
        cmd.extend([
            "-v", f"{self.cwd}:{WORK_DIR}",
            "--workdir", WORK_DIR,
            "--entrypoint", "modelscan",
            self.scan_image,
            *docker_args,
        ])
        return cmd
