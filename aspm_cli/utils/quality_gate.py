"""CI/CD quality gate: tie uploads to one run (``cli_id``), then poll the backend's verdict.

The backend evaluates every uploaded scan against the policy thresholds configured in
AccuKnox and reports one verdict per run at ``GET /api/v1/cicd/scan-status/``. Nothing
here knows what the thresholds are: the CLI only declares which scans a run will upload,
waits for the verdict and turns it into an exit code.

Exit codes: 0 pass / warn, 1 policy failure (blocking), 2 operational failure (a scan could
not be evaluated, the gate could not be reached or did not resolve in time).
"""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Mapping

import requests
from colorama import Fore

from aspm_cli.utils.common import _build_endpoint_url
from aspm_cli.utils.ingest_identity import derive_repository
from aspm_cli.utils.logger import Logger

EXIT_PASS = 0
EXIT_POLICY_FAILED = 1
EXIT_OPERATIONAL = 2

# Upload ``data_type`` values the backend gate evaluates (CicdScanner on the backend).
GATE_SCANNERS = ("SG", "SQ", "TR", "IAC", "TruffleHog", "DS", "SBOM")

DEFAULT_GATE_TIMEOUT = 300
POLL_INTERVAL = 5
MAX_POLL_INTERVAL = 10
# The backend registers the run synchronously during the upload, so a 404 that persists
# means the run was never created (e.g. a backend without quality gates ignores cli_id).
NOT_FOUND_LIMIT = 6

# Stable namespace so every step of one CI run derives the same cli_id.
_CLI_ID_NAMESPACE = uuid.UUID("6f1c5b4e-2a93-4d0e-9c4a-7b1e3f0d8a52")


class GateConfigError(ValueError):
    """The run cannot be gated as configured (bad cli_id, no repository, unsupported scan)."""


# ---------------------------------------------------------------- run identity


def _ci_run_identity(env: Mapping[str, str]) -> str:
    """Identity of the current CI run, or '' outside CI."""
    if env.get("GITHUB_RUN_ID"):
        return "|".join(("github", env.get("GITHUB_REPOSITORY", ""), env["GITHUB_RUN_ID"], env.get("GITHUB_RUN_ATTEMPT", "1")))
    if env.get("CI_PIPELINE_ID"):
        return "|".join(("gitlab", env.get("CI_PROJECT_ID", ""), env["CI_PIPELINE_ID"]))
    if env.get("BITBUCKET_PIPELINE_UUID"):
        return "|".join(("bitbucket", env.get("BITBUCKET_REPO_FULL_NAME", ""), env["BITBUCKET_PIPELINE_UUID"]))
    if env.get("BUILD_BUILDID"):
        return "|".join(("azure", env.get("SYSTEM_TEAMPROJECTID", ""), env["BUILD_BUILDID"]))
    if env.get("BUILD_TAG") or env.get("BUILD_URL"):
        return "|".join(("jenkins", env.get("BUILD_TAG") or env["BUILD_URL"]))
    return ""


def resolve_cli_id(explicit: str | None = None, env: Mapping[str, str] | None = None) -> str:
    """The run id shared by every upload and the poll of one pipeline run.

    Explicit value (``--cli-id`` / ``ACCUKNOX_CLI_ID``) wins. Otherwise it is derived from the CI
    run identity, so separate steps and jobs of the same run agree without passing outputs
    around. Outside CI a random id is used (it is logged so a later ``gate`` call can reuse it).
    """
    env = os.environ if env is None else env
    value = (explicit or env.get("ACCUKNOX_CLI_ID") or "").strip()
    if value:
        try:
            return str(uuid.UUID(value))
        except ValueError:
            raise GateConfigError(f"cli_id must be a UUID, got '{value}'.") from None
    identity = _ci_run_identity(env)
    return str(uuid.uuid5(_CLI_ID_NAMESPACE, identity)) if identity else str(uuid.uuid4())


# --------------------------------------------------------------- upload params


def normalize_scanners(scanners) -> list[str]:
    """Comma string or iterable -> de-duplicated list in input order, validated."""
    parts = scanners.split(",") if isinstance(scanners, str) else list(scanners)
    result = list(dict.fromkeys(part.strip() for part in parts if part and part.strip()))
    unknown = [part for part in result if part not in GATE_SCANNERS]
    if unknown:
        raise GateConfigError(
            f"Scan type(s) not covered by the quality gate: {', '.join(unknown)}. "
            f"Gated types: {', '.join(GATE_SCANNERS)}."
        )
    if not result:
        raise GateConfigError("The quality gate needs at least one scan type (e.g. SG,TR,IAC).")
    return result


def gate_upload_params(cli_id: str, scanners, identity: Mapping[str, str], repository: str | None = None) -> dict:
    """Upload query params for a gated scan: the repo identity plus run id, scanners and repository.

    The backend cannot match a policy scope (``repository:branch``) without a repository and branch
    and would leave the poll waiting, so a missing one is reported here instead.
    """
    params = dict(identity)
    repository = (repository or os.environ.get("ACCUKNOX_REPOSITORY") or "").strip() or derive_repository(
        params.get("repo_url", "")
    )
    missing = [name for name, value in (("repository", repository), ("branch", params.get("branch"))) if not value]
    if missing:
        raise GateConfigError(
            f"The quality gate needs the {' and '.join(missing)} to match policies, and it could not be detected. "
            "Run inside a git checkout or set ACCUKNOX_REPO_URL / ACCUKNOX_REPOSITORY and ACCUKNOX_BRANCH."
        )
    params.update(cli_id=cli_id, scanners=",".join(normalize_scanners(scanners)), repository=repository)
    return params


# ---------------------------------------------------------------------- poll


@dataclass
class GateResult:
    """How polling ended. ``payload`` is the last response body from the backend ({} if none)."""

    state: str  # resolved | timeout | unsupported | rejected
    payload: dict = field(default_factory=dict)
    detail: str = ""


def poll_gate(
    config: Mapping[str, str | None],
    cli_id: str,
    timeout: float = DEFAULT_GATE_TIMEOUT,
    interval: float = POLL_INTERVAL,
    *,
    http_get: Callable = requests.get,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> GateResult:
    """Poll the run until the backend marks it ``ready`` or the deadline passes.

    Transient failures (connection errors, 5xx) are retried until the deadline. A 400/401/403 is
    final, and a 404 that persists is reported as an unsupported backend.
    """
    logger = Logger.get_logger()
    url = _build_endpoint_url(config["accuknox_endpoint"], "/api/v1/cicd/scan-status/")
    # The poll API identifies a user, which the CLI's upload token does not, so it can take its own token.
    gate_token = config.get("accuknox_gate_token")
    headers = {"Authorization": f"Bearer {gate_token or config['accuknox_token']}"}
    if config.get("accuknox_tenant"):
        headers["Tenant-Id"] = str(config["accuknox_tenant"])

    deadline = clock() + timeout
    wait = interval
    not_found = 0
    payload: dict = {}
    detail = ""
    last_pending = None
    while True:
        try:
            response = http_get(url, headers=headers, params={"cli_id": cli_id}, timeout=(10, 30), verify=False)
        except requests.RequestException as exc:
            detail = f"{type(exc).__name__}: {exc}"
            logger.debug(f"Quality gate poll failed, retrying: {detail}")
        else:
            status = response.status_code
            if status == 200:
                payload = response.json()
                if payload.get("ready"):
                    return GateResult("resolved", payload)
                pending = payload.get("pending") or []
                if pending != last_pending:
                    last_pending = pending
                    logger.info(f"Waiting for the quality gate ({payload.get('message') or ', '.join(pending)})")
            elif status == 404:
                not_found += 1
                detail = "no scan run exists for this cli_id"
                if not_found >= NOT_FOUND_LIMIT:
                    return GateResult(
                        "unsupported",
                        detail=(
                            "The backend has no quality-gate run for this cli_id. Either no scan was uploaded with it, "
                            "or the backend does not support quality gates yet."
                        ),
                    )
            elif status in (400, 401, 403):
                detail = _error_detail(response)
                if status in (401, 403) and not gate_token:
                    detail += (
                        ". The token that uploads results may not be accepted by the quality-gate API, "
                        "which needs a user token: set ACCUKNOX_GATE_TOKEN (or --gate-token)"
                    )
                return GateResult("rejected", detail=detail)
            else:
                detail = f"HTTP {status}"
                logger.debug(f"Quality gate poll returned {detail}, retrying")
        if clock() + wait > deadline:
            return GateResult("timeout", payload, detail)
        sleep(wait)
        wait = min(wait * 1.3, MAX_POLL_INTERVAL)


def _error_detail(response) -> str:
    try:
        body = response.json()
        text = body.get("detail") or body
    except ValueError:
        text = response.text[:200]
    return f"HTTP {response.status_code}: {text}"


# ------------------------------------------------------------------- verdict


def decide(result: GateResult, softfail: bool = False, on_timeout: str = "fail") -> int:
    """Exit code for a poll result, following the action the backend returned.

    ``softfail`` only relaxes a policy failure (exit 1), the same as for local severity gates:
    a scan that could not be evaluated is operational and always fails.
    """
    if result.state == "timeout":
        return EXIT_PASS if on_timeout == "pass" else EXIT_OPERATIONAL
    if result.state != "resolved":
        return EXIT_OPERATIONAL

    payload = result.payload
    status = payload.get("status")
    if payload.get("failures") or status == "error":
        return EXIT_OPERATIONAL
    if status == "failed" or payload.get("blocking"):
        return EXIT_PASS if softfail else EXIT_POLICY_FAILED
    return EXIT_PASS  # passed, or passed with warnings


def _reason_line(reason: Mapping) -> str:
    detail = f"{reason.get('param', '?')} found {reason.get('found', '?')} > threshold {reason.get('threshold', '?')}"
    return f"{reason.get('policy') or 'policy'} [{reason.get('action') or '?'}]: {detail}"


def _counts_text(counts: Mapping) -> str:
    return " ".join(f"{name[0].upper()}:{counts.get(name, 0)}" for name in ("critical", "high", "medium", "low"))


def summary_lines(result: GateResult, exit_code: int, softfail: bool = False) -> list[str]:
    """Plain-text report of a poll result (also the body of the Markdown step summary)."""
    if result.state != "resolved":
        reason = {
            "timeout": "The quality gate did not resolve before the timeout"
            + (f" (last error: {result.detail})" if result.detail else "."),
            "unsupported": result.detail,
            "rejected": f"The backend rejected the quality gate request ({result.detail}).",
        }[result.state]
        return [reason]

    payload = result.payload
    lines = []
    for name, row in (payload.get("results") or {}).items():
        lines.append(f"{name:<10} {str(row.get('status')).upper():<8} {_counts_text(row.get('counts') or {})}")
        lines.extend(f"    - {_reason_line(reason)}" for reason in row.get("reasons") or [])
        failure_codes = {failure.get("code") for failure in payload.get("failures") or []}
        if row.get("note") and row["note"] not in failure_codes:
            lines.append(f"    - {row['note']}")
    overall = payload.get("overall") or {}
    if overall.get("status") in ("fail", "warn"):
        lines.append(f"overall    {overall['status'].upper():<8} {_counts_text(overall.get('combined_counts') or {})}")
        lines.extend(f"    - {_reason_line(reason)}" for reason in overall.get("reasons") or [])
    lines.extend(f"{failure['scanner']}: {failure['reason']}" for failure in payload.get("failures") or [])
    # The label is the backend's verdict; the exit code only says whether the build is blocked.
    verdict = {"passed": "passed", "warning": "warning", "failed": "failed"}.get(payload.get("status"), "error")
    if exit_code == EXIT_PASS and verdict in ("failed", "error"):
        verdict += " (soft fail: not blocking the build)"
    lines.append(f"Quality gate {verdict}: {payload.get('message', '')}".rstrip(": "))
    return lines


def report(result: GateResult, exit_code: int, softfail: bool = False) -> None:
    """Log the verdict, emit CI annotations and write the GitHub step summary when available."""
    logger = Logger.get_logger()
    lines = summary_lines(result, exit_code, softfail)
    warned = result.state == "resolved" and bool(result.payload.get("warnings"))
    color = Fore.GREEN if exit_code == EXIT_PASS and not warned else Fore.YELLOW if exit_code == EXIT_PASS else Fore.RED
    for line in lines[:-1]:
        logger.info(line)
    Logger.log_with_color("ERROR" if exit_code else "INFO", lines[-1], color)

    if os.environ.get("GITHUB_ACTIONS") == "true":
        level = "error" if exit_code else "warning" if (warned or softfail and result.payload.get("status") == "failed") else None
        if level:
            print(f"::{level} title=AccuKnox quality gate::{lines[-1]}")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as handle:
                handle.write("### AccuKnox quality gate\n\n```\n" + "\n".join(lines) + "\n```\n")
        except OSError as exc:
            logger.debug(f"Could not write the step summary: {exc}")
