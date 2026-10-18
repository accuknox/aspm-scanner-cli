import os
import sys

from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.quality_gate import (
    DEFAULT_GATE_TIMEOUT,
    EXIT_OPERATIONAL,
    GateConfigError,
    decide,
    poll_gate,
    report,
    resolve_cli_id,
)


def add_gate_arguments(parser):
    """Options that control how the verdict is awaited and applied (shared with ``pipeline``)."""
    parser.add_argument(
        "--gate-timeout",
        type=int,
        default=DEFAULT_GATE_TIMEOUT,
        help=f"Seconds to wait for the quality gate verdict (default: {DEFAULT_GATE_TIMEOUT}).",
    )
    parser.add_argument(
        "--gate-token",
        help="User token for the quality-gate API when the upload token is not accepted there "
        "(default: ACCUKNOX_GATE_TOKEN, else the upload token).",
    )
    parser.add_argument(
        "--gate-on-timeout",
        choices=["fail", "pass"],
        default="fail",
        help="What to do when the verdict does not arrive in time (default: fail).",
    )


class GateCommand(BaseCommand):
    help_text = "Wait for the quality gate verdict of a run and fail the build accordingly"

    def configure_parser(self, parser):
        parser.add_argument("--endpoint", help="The URL of the Control Panel.")
        parser.add_argument("--token", help="The token for authenticating with the Control Panel.")
        parser.add_argument("--tenant", help="Tenant ID [Optional]")
        parser.add_argument(
            "--cli-id",
            help="Run id of the scans to wait for (default: ACCUKNOX_CLI_ID, else derived from the CI run).",
        )
        parser.add_argument(
            "--softfail",
            action="store_true",
            help="Report a policy failure without failing the build (scans that could not be evaluated still fail).",
        )
        add_gate_arguments(parser)
        parser.set_defaults(func=self.execute)

    def execute(self, args):
        softfail = args.softfail or os.getenv("SOFT_FAIL") == "TRUE"
        config = {
            "accuknox_endpoint": args.endpoint or os.getenv("ACCUKNOX_ENDPOINT"),
            "accuknox_token": args.token or os.getenv("ACCUKNOX_TOKEN"),
            "accuknox_tenant": args.tenant or os.getenv("ACCUKNOX_TENANT"),
            "accuknox_gate_token": args.gate_token or os.getenv("ACCUKNOX_GATE_TOKEN"),
        }
        try:
            if not config["accuknox_endpoint"] or not (config["accuknox_token"] or config["accuknox_gate_token"]):
                raise GateConfigError("The endpoint and a token are required (--endpoint/--token or ACCUKNOX_*).")
            cli_id = resolve_cli_id(args.cli_id)
        except GateConfigError as exc:
            Logger.get_logger().error(str(exc))
            sys.exit(EXIT_OPERATIONAL)

        Logger.get_logger().info(f"Waiting up to {args.gate_timeout}s for the quality gate of run {cli_id}...")
        result = poll_gate(config, cli_id, timeout=args.gate_timeout)
        exit_code = decide(result, softfail, args.gate_on_timeout)
        report(result, exit_code, softfail)
        sys.exit(exit_code)
