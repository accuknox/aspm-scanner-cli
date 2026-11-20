import subprocess
import json
import os
import re
import shlex
import tempfile
import uuid
from aspm_cli.tool.manager import ToolManager
from aspm_cli.utils.logger import Logger
from aspm_cli.utils import docker_pull
from aspm_cli.utils import config
from aspm_cli.utils.subprocess_utils import utf8_text
from aspm_cli.utils.certin_sbom import TRIVY_FORMAT
from aspm_cli.utils.sbom import (
    DOCKER_WORKDIR,
    FILESYSTEM_SUBCOMMANDS,
    append_sbom_scanner_flags,
    append_vex_flags,
    normalize_sbom_args_for_docker,
    parse_trivy_subcommand,
    scan_root_from_command,
    scan_target_from_command,
)
from aspm_cli.utils.sbom_license_merge import (
    should_enrich_filesystem_licenses,
    should_merge_syft,
    syft_scan_source,
)
from aspm_cli.utils.sbom_merge import (
    append_components,
    build_delta_bom,
    count_components,
    link_added_components,
    merge_components,
    merge_into_spdx,
    merge_vulnerabilities,
)
from aspm_cli.inference import infer_dependencies
from aspm_cli.inference.base import normalize_dep_name
from aspm_cli.scan.trivy_runner import _fix_result_file_permissions_if_docker
from aspm_cli.utils.docker_runtime import build_docker_run_prefix, trivy_scan_needs_docker_socket
from colorama import Fore

class ContainerScanner:
    ak_container_image = os.getenv("SCAN_IMAGE", "public.ecr.aws/k9v9d5v2/accuknox/trivy:0.69.3")
    ak_syft_image = os.getenv("SYFT_IMAGE", "anchore/syft:v1.42.3")
    result_file = './results.json'
    trivy_cache_dir = '/root/.cache/trivy'

    def __init__(
        self,
        command,
        container_mode=False,
        generate_sbom: bool = False,
        sbom_format: str = "cyclonedx",
        vex_files=None,
        enrich_licenses: bool = False,
        syft_merge: bool = True,
        infer_deps: bool = True,
    ):
        self.vex_files = list(vex_files or [])
        self.syft_merge = syft_merge
        self.infer_deps = infer_deps
        self._syft_doc = None
        self._cache_volume = None
        self.command = command
        self.container_mode = container_mode
        self.generate_sbom = generate_sbom
        self.sbom_format = sbom_format
        self.enrich_licenses = enrich_licenses

    def run(self):
        # In container mode every scanner run is a fresh container, so the Trivy database would be
        # downloaded again for the advisory lookup of the merged components. One throw-away volume,
        # shared by this scan's runs and removed afterwards, avoids the second download.
        if self.container_mode and self.generate_sbom and self._merge_planned():
            self._cache_volume = f"accuknox-trivy-cache-{uuid.uuid4().hex[:12]}"
        try:
            return self._run()
        finally:
            self._drop_cache_volume()

    def _merge_planned(self):
        return should_merge_syft(self.command) and (self.syft_merge or self.enrich_licenses or self.infer_deps)

    def _with_cache(self, cmd):
        """Add the shared Trivy cache volume to a ``docker run`` command (no-op otherwise)."""
        if not self._cache_volume or cmd[:3] != ["docker", "run", "--rm"]:
            return cmd
        return [*cmd[:3], "-v", f"{self._cache_volume}:{self.trivy_cache_dir}", *cmd[3:]]

    def _drop_cache_volume(self):
        volume, self._cache_volume = self._cache_volume, None
        if not volume:
            return
        try:
            subprocess.run(["docker", "volume", "rm", "-f", volume], capture_output=True, timeout=60)
        except Exception as e:
            Logger.get_logger().debug(f"Could not remove cache volume {volume}: {e}")

    def _run(self):
        try:
            if self.container_mode:
                docker_pull(self.ak_container_image)

            severity_threshold, sanitized_args = self._build_container_scan_args()
            scan_cmd = self._build_scan_command(sanitized_args)

            log_msg = (
                "Running container SBOM scan"
                if self.generate_sbom
                else "Scanning container image"
            )
            Logger.get_logger().debug(f"{log_msg}: {' '.join(scan_cmd)}")
            result = subprocess.run(scan_cmd, capture_output=True, **utf8_text())

            if result.stdout:
                sanitized_stdout = re.sub(
                    r"trivy|aquasecurity|aqua security",
                    "[scanner]",
                    result.stdout,
                    flags=re.IGNORECASE,
                )
                Logger.get_logger().debug(sanitized_stdout)
                if("--help" in self.command):
                    Logger.log_with_color('INFO', sanitized_stdout, Fore.WHITE)
                    return config.PASS_RETURN_CODE, None
            if result.stderr:
                sanitized_stderr = re.sub(
                    r"trivy|aquasecurity|aqua security",
                    "[scanner]",
                    result.stderr,
                    flags=re.IGNORECASE,
                )
                # The scanner writes its progress and warnings to stderr on success too; only a
                # failed run is an error.
                if result.returncode == 0:
                    Logger.get_logger().warning(sanitized_stderr)
                else:
                    Logger.get_logger().error(sanitized_stderr)

            if self.generate_sbom:
                # SBOM mode: Always use self.result_file (forced to ./results.json)
                if os.path.exists(self.result_file):
                    # Trivy ran as root in Docker, so the host cannot rewrite its output (project_name/classifier
                    # enrichment would silently fail); hand the file back first.
                    _fix_result_file_permissions_if_docker(self.container_mode, self.result_file)
                    if result.returncode == 0:
                        merge_rc = self._merge_inventory()
                        if merge_rc != 0:
                            return merge_rc, self.result_file
                    return result.returncode, self.result_file
                return result.returncode, None

            if not os.path.exists(self.result_file):
                return config.SOMETHING_WENT_WRONG_RETURN_CODE, None

            severity_threshold = [s.strip().upper() for s in (severity_threshold or "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL").split(',')]
            if self._severity_threshold_met(severity_threshold):
                Logger.get_logger().error(f"Vulnerabilities matching severities: {', '.join(severity_threshold)} found.")
                return 1, self.result_file

            return 0, self.result_file
        except Exception as e:
            Logger.get_logger().error(f"Error during container scan: {e}")
            raise

    def _build_container_scan_args(self):
        """
        Parses the raw command, strips forbidden arguments, and enforces
        the required output format and file. This ensures the class can
        reliably find the JSON output for vulnerability scans.
        """
        if self.generate_sbom:
            # SBOM mode: force the chosen SBOM standard (JSON) and the fixed output file
            original_args = shlex.split(self.command or "")
            # Strip any existing format/output flags
            flags_to_strip = {"-o", "--output", "-f", "--format"}
            sanitized_args = []
            i = 0
            while i < len(original_args):
                arg = original_args[i]
                if arg in flags_to_strip:
                    i += 2  # Skip flag and value
                    continue
                sanitized_args.append(arg)
                i += 1
            # Force cyclonedx format and JSON output
            sanitized_args.extend(["-f", TRIVY_FORMAT.get(self.sbom_format, "cyclonedx"), "-o", self.result_file])
            sanitized_args = append_sbom_scanner_flags(sanitized_args)
            sanitized_args = append_vex_flags(sanitized_args, self.vex_files, self.container_mode)
            if self.container_mode:
                sanitized_args = normalize_sbom_args_for_docker(
                    self.command or "", sanitized_args
                )
            return None, sanitized_args

        # Flags that take a value and should be removed.
        flags_to_strip = {"-s", "--severity", "-o", "--output", "-f", "--format", "--exit-code", "--quiet"}
        severity_threshold = None

        # Use shlex to handle quotes and spaces correctly
        original_args = shlex.split(self.command)
        sanitized_args = []
        
        i = 0
        while i < len(original_args):
            arg = original_args[i]
            # If the arg is a flag to strip, skip it and its value
            if arg in flags_to_strip:
                if arg in ("-s", "--severity"):
                    if i + 1 < len(original_args):
                        severity_threshold = original_args[i + 1]
                i += 2
                continue
            
            sanitized_args.append(arg)
            i += 1

        sanitized_args.extend(["--quiet", "--exit-code", "1", "-f", "json", "-o", self.result_file])
        return severity_threshold, sanitized_args
    
    def _build_scan_command(self, container_scan_args):
        if not self.container_mode:
            cmd = ([ToolManager.get_path("container")])
        else:
            cmd = build_docker_run_prefix(
                workdir="/workdir",
                mount_docker_socket=trivy_scan_needs_docker_socket(container_scan_args),
            )
            cmd.append(self.ak_container_image)
        
        cmd.extend(container_scan_args)
        return self._with_cache(cmd)

    def _enrich_licenses_from_syft(self):
        """
        Run Syft over what Trivy scanned and keep its CycloneDX in ``self._syft_doc``.

        Runs by default (``syft_merge``); ``--enrich-licenses`` is the older explicit form and keeps
        its strictness: a missing Syft fails the scan only when that flag was passed. Otherwise a
        missing or failing Syft is a warning and the Trivy SBOM stands on its own.
        """
        self._syft_doc = None
        if not (self.enrich_licenses or self.syft_merge):
            return 0
        if not should_merge_syft(self.command):
            if self.enrich_licenses:
                Logger.get_logger().warning(
                    "--enrich-licenses applies to filesystem, rootfs and image SBOMs; skipping Syft."
                )
            return 0
        target = scan_target_from_command(self.command)
        if not target or target.startswith("-"):
            Logger.get_logger().warning("Could not tell what to inventory from the command; skipping Syft.")
            return 0
        try:
            completed = self._run_syft()
        except FileNotFoundError:
            if self.enrich_licenses:
                Logger.get_logger().error(
                    "Syft is required for --enrich-licenses. "
                    "Run `accuknox-aspm-scanner tool install --type syft`."
                )
                return config.SOMETHING_WENT_WRONG_RETURN_CODE
            Logger.get_logger().warning(
                "Syft is not installed; the SBOM is built without its inventory. "
                "Run `accuknox-aspm-scanner tool install --type syft` to include it."
            )
            return 0
        except Exception as e:
            Logger.get_logger().warning(f"Syft inventory failed ({e}); continuing with Trivy SBOM.")
            return 0

        rc = completed if isinstance(completed, int) else completed.returncode
        if rc != 0:
            Logger.get_logger().warning("Syft inventory failed; continuing with Trivy SBOM.")
            return 0
        try:
            loaded = json.loads(getattr(completed, "stdout", "") or "{}")
            if isinstance(loaded, dict):
                self._syft_doc = loaded
        except Exception as e:
            Logger.get_logger().warning(f"Could not read Syft inventory ({e}); continuing with Trivy SBOM.")
        return 0

    def _scan_root(self):
        """Host directory the scan covers (what inference reads)."""
        return scan_root_from_command(self.command)

    def _merge_inventory(self):
        """
        SBOM: fold Syft's inventory (and, for a filesystem, source-inferred dependencies) into the
        Trivy document. CycloneDX also gets advisories for the components Trivy never saw; SPDX
        cannot carry vulnerabilities, so it gets the added packages only.

        Every step after the Trivy scan is best-effort: a failure leaves the Trivy SBOM as it was.
        """
        if not self.generate_sbom:
            return 0
        use_syft = self.syft_merge or self.enrich_licenses
        subcommand = parse_trivy_subcommand(self.command)
        infer = self.infer_deps and subcommand in FILESYSTEM_SUBCOMMANDS
        if not should_merge_syft(self.command):
            if self.enrich_licenses:
                return self._enrich_licenses_from_syft()  # warns and skips
            return 0
        if not use_syft and not infer:
            return 0

        try:
            with open(self.result_file, "r", encoding="utf-8") as handle:
                doc = json.load(handle)
        except Exception as e:
            Logger.get_logger().warning(f"Could not read the SBOM to merge ({e}); keeping Trivy SBOM.")
            return 0
        if not isinstance(doc, dict):
            return 0
        spdx = "spdxVersion" in doc

        if use_syft:
            rc = self._enrich_licenses_from_syft()
            if rc != 0:
                return rc

        names = {
            normalize_dep_name(c.get("name", ""))
            for c in (doc.get("packages") if spdx else doc.get("components")) or []
            if isinstance(c, dict)
        }
        if self._syft_doc:
            names |= {normalize_dep_name(c.get("name", "")) for c in self._syft_doc.get("components") or []
                      if isinstance(c, dict) and c.get("type") != "file"}
        inferred = []
        if infer:
            try:
                inference = infer_dependencies(self._scan_root(), names)
                inferred = [d.to_component() for d in inference.deps]
                if inference.deps:
                    Logger.get_logger().info(
                        f"Inferred {len(inference.deps)} dependencies from source "
                        f"({len(inference.eligible())} with a resolved version)."
                    )
                if inference.unresolved_includes:
                    Logger.get_logger().debug(f"{len(inference.unresolved_includes)} includes matched no known package.")
            except Exception as e:
                Logger.get_logger().warning(f"Source dependency inference failed ({e}); continuing without it.")

        if not self._syft_doc and not inferred:
            return 0

        if spdx:
            stats = merge_into_spdx(doc, self._syft_doc, inferred)
            message = f"Merged SPDX SBOM: {len(doc.get('packages') or [])} packages (+{stats['added']} added)"
        else:
            original_refs = {c.get("bom-ref") for c in doc.get("components") or [] if isinstance(c, dict)}
            syft_stats = inferred_stats = None
            if self._syft_doc:
                _, syft_stats = merge_components(doc, self._syft_doc, "inventory")
            if inferred:
                inferred_stats = append_components(doc, inferred, "source-inference")
            link_added_components(doc, original_refs)
            delta = build_delta_bom(doc, original_refs)
            if delta:
                findings = self._lookup_delta_findings(delta)
                if findings:
                    added = merge_vulnerabilities(doc, findings)
                    Logger.get_logger().info(f"Added {added} findings for components found by the extra inventory.")
            message = (
                f"Merged SBOM: {count_components(doc)} components"
                + (f" (+{syft_stats['added']} from inventory)" if syft_stats else "")
                + (f" (+{inferred_stats['added']} inferred from source)" if inferred_stats else "")
            )
        try:
            with open(self.result_file, "w", encoding="utf-8") as handle:
                json.dump(doc, handle, indent=2)
        except OSError as e:
            Logger.get_logger().warning(f"Could not write the merged SBOM ({e}); keeping Trivy SBOM.")
            return 0
        Logger.get_logger().info(message)
        return 0

    def _lookup_delta_findings(self, delta):
        """Run the scanner's SBOM mode over ``delta`` (outside the scanned tree) and return its CycloneDX."""
        try:
            with tempfile.TemporaryDirectory(prefix="accuknox-delta-") as tmp:
                with open(os.path.join(tmp, "delta.json"), "w", encoding="utf-8") as handle:
                    json.dump(delta, handle)
                os.chmod(tmp, 0o777)
                scan_args = ["sbom", "delta.json" if self.container_mode else os.path.join(tmp, "delta.json"),
                             "--scanners", "vuln", "--quiet", "-f", "cyclonedx",
                             "-o", "findings.json" if self.container_mode else os.path.join(tmp, "findings.json")]
                if self.container_mode:
                    cmd = build_docker_run_prefix(workdir="/workdir", host_path=tmp)
                    cmd.append(self.ak_container_image)
                else:
                    cmd = [ToolManager.get_path("container")]
                cmd.extend(scan_args)
                done = subprocess.run(self._with_cache(cmd), capture_output=True, **utf8_text())
                out = os.path.join(tmp, "findings.json")
                if done.returncode != 0 or not os.path.exists(out):
                    Logger.get_logger().warning("Advisory lookup for the extra components failed; they are listed without findings.")
                    return None
                with open(out, "r", encoding="utf-8") as handle:
                    return json.load(handle)
        except Exception as e:
            Logger.get_logger().warning(f"Advisory lookup for the extra components failed ({e}).")
            return None

    def _run_syft(self):
        if self.container_mode:
            docker_pull(self.ak_syft_image)
        scan_cmd = self._build_syft_command()
        Logger.get_logger().debug(f"Running Syft inventory: {' '.join(scan_cmd)}")
        return subprocess.run(scan_cmd, capture_output=True, **utf8_text())

    def _build_syft_command(self):
        source = syft_scan_source(self.command, self.container_mode)
        if self.container_mode:
            # An image is read through the host's Docker daemon; a directory through the /workdir mount.
            cmd = build_docker_run_prefix(workdir="/workdir", mount_docker_socket=parse_trivy_subcommand(self.command) == "image")
            cmd.append(self.ak_syft_image)
        else:
            cmd = [ToolManager.get_path("syft")]
        # The inventory is read from stdout, so nothing is written into the scanned directory.
        cmd.extend([source, "--enrich", "all", "-o", "cyclonedx-json", "-q"])
        return cmd

    def _severity_threshold_met(self, severity_threshold):
        try:
            with open(self.result_file, 'r') as f:
                data = json.load(f)

            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    if vuln.get("Severity", "").upper() in severity_threshold:
                        return True
            return False
        except Exception as e:
            Logger.get_logger().error(f"Error reading scan results: {e}")
            raise

