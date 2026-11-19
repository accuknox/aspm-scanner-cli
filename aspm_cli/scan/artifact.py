"""Local artifact scanning and the authenticated on-demand scan API client."""
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import requests

from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils.artifact_engine import ArtifactError, native_executor, result_exit_code, scan_artifact
from aspm_cli.utils.common import _build_endpoint_url
from aspm_cli.utils.docker_runtime import docker_volume_mount
from aspm_cli.utils.logger import Logger


class ArtifactClient:
    def __init__(self, config):
        self.base = _build_endpoint_url(config["accuknox_endpoint"].rstrip("/"), "/api/v1/artifact-scans")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f'Bearer {config["accuknox_token"]}'
        tenant = config.get("accuknox_tenant")
        self.params = {"tenant_id": tenant} if tenant else {}
        if tenant:
            self.session.headers["Tenant-Id"] = str(tenant)

    def request(self, method, route, **kwargs):
        try:
            response = self.session.request(method, self.base + route, params=self.params,
                                            timeout=(15, 300), allow_redirects=False, **kwargs)
            if response.status_code == 404:
                raise ArtifactError("This deployment does not support artifact scans. Upgrade the backend first.")
            response.raise_for_status()
            if 300 <= response.status_code < 400:
                raise ArtifactError("Artifact API redirected the request; check the endpoint URL.")
            return response
        except requests.RequestException as exc:
            raise ArtifactError("Artifact API request failed. Check endpoint, credentials, permissions, and server limits.") from exc

    def capabilities(self):
        return self.request("GET", "/capabilities").json()


def execute_artifact(args, config, softfail):
    mobile = args.scantype.upper() == "MOBILE"
    severities = {s.strip().upper() for s in getattr(args, "severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL").split(",")}
    if not severities or not severities <= {"UNKNOWN", "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ArtifactError("Invalid severity list.")
    if mobile and args.skip_upload:
        raise ArtifactError("Mobile analysis runs on the backend and cannot use --skip-upload.")
    if not args.skip_upload:
        if not all(config.get(key) for key in ("accuknox_endpoint", "accuknox_token")):
            raise ArtifactError("Endpoint and token are required for backend scans and result uploads.")
        if not (mobile and args.run_id) and not all(config.get(key) for key in ("accuknox_label", "accuknox_project_name")):
            raise ArtifactError("Project name and label are required for artifact uploads.")
        client = ArtifactClient(config)
        capabilities = client.capabilities()
        if capabilities.get("schema_version") != 1:
            raise ArtifactError("Backend artifact API version is incompatible with this CLI.")
    else:
        client = None
    output = Path(args.output_dir).expanduser().resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="accuknox-artifact-"))
    output.mkdir(parents=True, exist_ok=True)
    succeeded = False
    try:
        if mobile:
            if args.timeout <= 0:
                raise ArtifactError("Timeout must be positive.")
            if args.run_id:
                run_id = str(uuid.UUID(args.run_id))
                run = client.request("GET", f"/runs/{run_id}").json()
            else:
                path = Path(args.target).expanduser().resolve()
                if path.suffix.lower() not in {".apk", ".ipa"} or not path.is_file():
                    raise ArtifactError("Mobile targets must be APK or IPA files.")
                required = "dynamic" if args.mode == "static_dynamic" else "static" if args.mode == "static" else "sbom"
                if not capabilities.get("mobile", {}).get(required):
                    raise ArtifactError(f"Backend mobile {required} analysis is unavailable.")
                if path.stat().st_size > capabilities["max_upload_bytes"]:
                    raise ArtifactError("Artifact exceeds this deployment's upload limit.")
                with path.open("rb") as stream:
                    uploaded = client.request("POST", "/inputs", files={"file": (path.name, stream)},
                        data={"label": config["accuknox_label"]}).json()
                run = client.request("POST", "/runs", json={
                    "input_id": uploaded["id"], "project_name": config["accuknox_project_name"],
                    "label": config["accuknox_label"], "asset_name": args.asset_name or path.name,
                    "mode": args.mode, "dynamic_duration": args.dynamic_duration,
                    "idempotency_key": args.idempotency_key or str(uuid.uuid4()),
                }).json()
            Logger.get_logger().info(f'Artifact scan run: {run["id"]}')
            deadline = time.monotonic() + args.timeout
            while not args.no_wait and run["status"] in {"queued", "running"}:
                if time.monotonic() >= deadline:
                    raise ArtifactError(f'Wait timed out. Retrieve the run with --run-id {run["id"]}.')
                time.sleep(3)
                run = client.request("GET", f'/runs/{run["id"]}').json()
            (output / "result.json").write_text(json.dumps(run, indent=2), encoding="utf-8")
            if args.no_wait:
                succeeded = True
                return 0
            for name in ("report", "sbom"):
                if run.get(f"has_{name}"):
                    response = client.request("GET", f'/runs/{run["id"]}/{name}')
                    (output / f"{name}.json").write_bytes(response.content)
            result = run
        else:
            target = Path(args.target).expanduser().absolute()
            cache = Path(args.cache_dir).expanduser().resolve() if args.cache_dir else Path.home() / ".cache" / "accuknox-artifacts"
            def execute(tool, tool_args, workdir):
                tool_args = list(tool_args)
                if tool == "trivy":
                    tool_args.extend(["--cache-dir", str(cache)])
                    if args.offline:
                        tool_args.extend(["--skip-db-update", "--skip-java-db-update", "--offline-scan"])
                if not args.container_mode:
                    native_executor(ToolManager.get_path("syft" if tool == "syft" else "container"), tool_args, workdir)
                    return
                cache.mkdir(parents=True, exist_ok=True)
                # Map host paths into portable Linux container paths, including
                # Windows drive-letter paths. Source and output mounts are separate.
                source_root = target if target.is_dir() else target.parent
                mounts = [(str(source_root), "/input"), (str(output), "/output"), (str(cache), "/cache")]
                command = ["docker", "run", "--rm", "-e", "HOME=/tmp", "-e", "XDG_CACHE_HOME=/cache"]
                if hasattr(os, "getuid"):
                    command.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
                for host, dest in mounts:
                    mounted = docker_volume_mount(host, dest)
                    if dest == "/input":
                        mounted[-1] += ":ro"
                    command.extend(mounted)
                for index, value in enumerate(tool_args):
                    for host, dest in sorted(mounts, key=lambda item: len(item[0]), reverse=True):
                        if host in value:
                            value = value.replace(host, dest).replace("\\", "/")
                    tool_args[index] = value
                image = os.getenv("SYFT_IMAGE", "anchore/syft:v1.42.3") if tool == "syft" else os.getenv("SCAN_IMAGE", "public.ecr.aws/k9v9d5v2/accuknox/trivy:0.69.3")
                try:
                    subprocess.run([*command, image, *tool_args], check=True, timeout=1200)
                except (OSError, subprocess.SubprocessError) as exc:
                    raise ArtifactError("Container scanner failed. Check Docker, images, and database caches.") from exc
            result = scan_artifact(target, output, args.target_type, args.asset_name,
                                   config.get("accuknox_project_name"), sbom_only=args.scantype.upper() == "SBOM", execute=execute)
            if client:
                with (output / "result.json").open("rb") as stream:
                    run = client.request("POST", "/runs", files={"report": ("result.json", stream, "application/json")}, data={
                        "project_name": config["accuknox_project_name"], "label": config["accuknox_label"],
                        "asset_name": result["artifact"]["name"], "mode": "sbom" if args.scantype.upper() == "SBOM" else "sca",
                        "idempotency_key": args.idempotency_key or str(uuid.uuid4()),
                    }).json()
                Logger.get_logger().info(f'Results submitted for ingestion: {run["id"]}')
                deadline = time.monotonic() + 1200
                while run["status"] in {"queued", "running"}:
                    if time.monotonic() >= deadline:
                        raise ArtifactError(f'Ingestion wait timed out; run {run["id"]}.')
                    time.sleep(3)
                    run = client.request("GET", f'/runs/{run["id"]}').json()
                if run["status"] != "completed":
                    raise ArtifactError(f'Backend ingestion did not complete; inspect run {run["id"]}.')
        severity = {s.strip().upper() for s in getattr(args, "severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL").split(",")}
        code = result_exit_code(result, severity, softfail)
        succeeded = code != 2
        return code
    finally:
        if args.keep_results or args.output_dir or mobile or not succeeded:
            Logger.get_logger().info(f"Results: {output}")
        else:
            shutil.rmtree(output)
