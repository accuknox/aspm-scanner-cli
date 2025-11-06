from pydantic import BaseModel, Field, validator
from typing import Literal, Optional

# Moved from original main.py / utils.py
ALLOWED_TOOL_TYPES = ["iac", "sast", "secret", "container", "dast", "sq-sast"]

class ToolDownloadConfig(BaseModel):
    tooltype: Optional[Literal[tuple(ALLOWED_TOOL_TYPES)]] = None
    all: bool = False

    @validator('tooltype', always=True)
    def check_tooltype_or_all(cls, v, values):
        if not v and not values.get('all'):
            raise ValueError('Either --type or --all must be specified.')
        if v and values.get('all'):
            raise ValueError('Cannot specify both --type and --all.')
        return v