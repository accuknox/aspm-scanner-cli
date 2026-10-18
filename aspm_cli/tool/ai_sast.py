"""Install the matching local CodeAssure and context-graph sources together."""
import os
from pathlib import Path
import subprocess
import sys

from aspm_cli.utils.logger import Logger


def install_ai_sast(install_dir, overwrite=False):
    if getattr(sys, "frozen", False) or sys.version_info < (3, 11):
        Logger.get_logger().error("AI SAST source installation requires Python 3.11+; install both CLIs in a Python environment and set CODEASSURE_EXECUTABLE.")
        return False
    root = Path(__file__).resolve().parents[3]
    codeassure = Path(os.getenv("CODEASSURE_SOURCE", str(root / "codeassure-cli"))).expanduser().resolve()
    graph = Path(os.getenv("CONTEXT_GRAPH_SOURCE", str(root / "code-context-graph"))).expanduser().resolve()
    if not all((path / "pyproject.toml").is_file() for path in (codeassure, graph)):
        Logger.get_logger().error("Set CODEASSURE_SOURCE and CONTEXT_GRAPH_SOURCE to the matching source checkouts before installing AI SAST.")
        return False
    environment = Path(install_dir) / "codeassure" / "venv"
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    try:
        if not python.is_file():
            subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
        subprocess.run([str(python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], check=True)
        subprocess.run([str(python), "-m", "pip", "install", "-e", str(graph), "-e", str(codeassure)], check=True)
        # Joern gives real data-flow graphs; without it context-graph falls back to tree-sitter.
        # Best effort: a missing JDK or offline install must not fail the AI SAST setup.
        joern = subprocess.run([str(python), "-m", "context_graph.cli", "install-joern"], check=False)
        if joern.returncode != 0:
            Logger.get_logger().warning("Joern was not installed; AI SAST will use degraded tree-sitter graphs. Run `context-graph install-joern` once a JDK 17+ is available.")
        return True
    except (OSError, subprocess.CalledProcessError):
        Logger.get_logger().error("AI SAST environment installation failed; see pip output above.")
        return False
