from .gate_command import GateCommand
from .pipeline_command import PipelineCommand
from .precommit_command import PreCommitCommand
from .scan_command import ScanCommand
from .tool_command import ToolCommand

command_registry = {
    "gate": GateCommand,
    "pipeline": PipelineCommand,
    "pre-commit": PreCommitCommand,
    "scan": ScanCommand,
    "tool": ToolCommand,
}