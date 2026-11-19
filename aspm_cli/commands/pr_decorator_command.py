import os
import sys

from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.pr_decorator import run as pr_decorator_run
from aspm_cli.pr_decorator.adapters import LOADERS_BY_SCANTYPE
from aspm_cli.pr_decorator.remediation import DEFAULT_BASE_URL, DEFAULT_MODEL
from aspm_cli.pr_decorator.render import DEFAULT_THRESHOLDS


class PRDecoratorCommand(BaseCommand):
    help_text = "Post scan findings as a PR review (summary comment + inline comments)"

    def configure_parser(self, parser):
        parser.add_argument(
            "--result-file", required=True,
            help="Scan result JSON, or a comma-separated list (one per scan type).",
        )
        parser.add_argument(
            "--scan-type",
            help=f"Comma-separated scan type per --result-file entry, e.g. 'sast,iac'. "
                 f"Allowed: {', '.join(LOADERS_BY_SCANTYPE)}. Omit to guess from filename.",
        )
        parser.add_argument(
            "--changed-files",
            help="Comma-separated changed files to scope findings to. "
                 "Auto-computed from the PR diff if omitted.",
        )
        parser.add_argument("--mode", choices=["advisory", "blocking"], default="advisory",
                             help="advisory = comment only. blocking = REQUEST_CHANGES "
                                  "when a threshold is exceeded.")
        parser.add_argument("--max-critical", type=int, default=DEFAULT_THRESHOLDS["CRITICAL"])
        parser.add_argument("--max-high", type=int, default=DEFAULT_THRESHOLDS["HIGH"])
        parser.add_argument("--max-medium", type=int, default=DEFAULT_THRESHOLDS["MEDIUM"])
        parser.add_argument("--max-low", type=int, default=DEFAULT_THRESHOLDS["LOW"])
        parser.add_argument("--github-token", help="Needs pull-requests:write. Defaults to $GITHUB_TOKEN.")
        parser.add_argument(
            "--llm-api-key",
            help="Optional. If set, calls an LLM to generate a remediation suggestion for SAST "
                 "findings with no native fix. Unset (default) = that step is skipped entirely - "
                 "no LLM call, no cost, findings post as-is. Defaults to $LLM_API_KEY/$OPENROUTER_API_KEY.",
        )
        parser.add_argument("--llm-model", default=None,
                             help=f"Only used if --llm-api-key is set. Default: {DEFAULT_MODEL}.")
        parser.add_argument("--llm-base-url", default=None,
                             help=f"Only used if --llm-api-key is set. Any OpenAI-compatible "
                                  f"chat-completions endpoint. Default: {DEFAULT_BASE_URL}.")
        parser.add_argument("--dry-run", action="store_true",
                             help="Print what would be posted, no API calls.")
        parser.set_defaults(func=self.execute)

    def execute(self, args):
        result_paths = [p for p in args.result_file.split(",") if p]
        scan_types = [t.strip() or None for t in args.scan_type.split(",")] if args.scan_type else None
        if scan_types and len(scan_types) != len(result_paths):
            self._fail("--scan-type must have the same number of entries as --result-file.")
        if scan_types:
            for t in scan_types:
                if t and t not in LOADERS_BY_SCANTYPE:
                    self._fail(f"Unknown --scan-type '{t}'. Allowed: {', '.join(LOADERS_BY_SCANTYPE)}.")

        changed_files = set(args.changed_files.split(",")) if args.changed_files else None
        thresholds = {
            "CRITICAL": args.max_critical, "HIGH": args.max_high,
            "MEDIUM": args.max_medium, "LOW": args.max_low, "UNKNOWN": None,
        }

        llm_api_key = args.llm_api_key or os.environ.get("LLM_API_KEY") or os.environ.get("OPENROUTER_API_KEY")

        exit_code = pr_decorator_run.run(
            result_paths, scan_types=scan_types, changed_files=changed_files, mode=args.mode,
            thresholds=thresholds, dry_run=args.dry_run, github_token=args.github_token,
            llm_api_key=llm_api_key,
            llm_model=args.llm_model or DEFAULT_MODEL,
            llm_base_url=args.llm_base_url or DEFAULT_BASE_URL,
        )
        if exit_code != 0:
            sys.exit(exit_code)

    @staticmethod
    def _fail(message):
        from aspm_cli.utils.logger import Logger
        Logger.get_logger().error(message)
        sys.exit(1)
