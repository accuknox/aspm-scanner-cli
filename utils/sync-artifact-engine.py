"""Sync the portable engine into a sibling backend checkout; --check for CI."""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--backend", type=Path, default=Path(__file__).resolve().parents[2] / "cspm-backend")
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
source = Path(__file__).resolve().parents[1] / "aspm_cli/utils/artifact_engine.py"
target = args.backend / "soarcast/playbook/integrations/artifact_engine.py"
if args.check:
    if source.read_bytes() != target.read_bytes():
        raise SystemExit("Artifact engines differ. Run utils/sync-artifact-engine.py.")
else:
    target.write_bytes(source.read_bytes())
