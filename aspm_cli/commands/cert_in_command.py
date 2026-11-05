import json
import sys

from aspm_cli.commands.base_command import BaseCommand
from aspm_cli.utils.certin_sbom import check_file, is_conformant, print_report


class CertInCheckCommand(BaseCommand):
    help_text = "Check a CycloneDX or SPDX SBOM file against the CERT-In minimum data fields"

    def configure_parser(self, parser):
        parser.add_argument("file", help="SBOM file: CycloneDX JSON, SPDX JSON or SPDX tag-value (.spdx).")
        parser.add_argument(
            "--json",
            dest="json_output",
            action="store_true",
            help="Print the full report as JSON on stdout instead of the summary.",
        )
        parser.set_defaults(func=self.execute)

    def execute(self, args):
        """Exit 0 when conformant, 1 when partially or not conformant, 2 when the file cannot be read."""
        try:
            report = check_file(args.file)
        except (OSError, ValueError) as exc:
            print(f"Cannot check {args.file}: {exc}", file=sys.stderr)
            raise SystemExit(2)
        if args.json_output:
            print(json.dumps(report, indent=2))
        else:
            print_report(report)
            attestation = report.get("attestation")
            if attestation:
                state = "matches" if attestation["matches"] else "DOES NOT match"
                print(f"The file's own CERT-In attestation ({attestation['claimed']}) {state} this check ({attestation['recomputed']}).")
        raise SystemExit(0 if is_conformant(report) else 1)
