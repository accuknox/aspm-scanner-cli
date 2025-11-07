from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Literal, Optional

ALLOWED_TOOL_TYPES = ["iac", "sast", "secret", "container", "dast", "sq-sast"]

class ToolDownloadConfig(BaseModel):
    tooltype: Optional[str] = Field(default=None)
    all: Optional[bool] = Field(default=False)

    @field_validator("tooltype")
    @classmethod
    def validate_tooltype(cls, v):
        if v and v not in ALLOWED_TOOL_TYPES:
            raise ValueError(f"Invalid tooltype. Allowed values: {', '.join(ALLOWED_TOOL_TYPES)}")
        return v

    @model_validator(mode="after")
    def validate_either_tooltype_or_all(self):
        if self.all and self.tooltype:
            raise ValueError("Cannot specify both --all and a tooltype at the same time.")
        if not self.all and not self.tooltype:
            raise ValueError("You must specify either a tooltype or use --all.")
        return self