from .precommit_command import PreCommitCommand
from .scan_command import ScanCommand
from .tool_command import ToolCommand

# Command Registry
command_registry = {
    "pre-commit": PreCommitCommand,
    "scan": ScanCommand,
    "tool": ToolCommand,
}