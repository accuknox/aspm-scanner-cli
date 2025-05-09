from pydantic import BaseModel, ValidationError, Field, field_validator, root_validator
import os
from typing import Optional
from aspm_cli.utils.logger import Logger


ALLOWED_SCAN_TYPES = {"iac"}

class Config(BaseModel):
    SCAN_TYPE: str
    ACCUKNOX_ENDPOINT: str
    ACCUKNOX_TENANT: int
    ACCUKNOX_LABEL: str
    ACCUKNOX_TOKEN: str
    SOFT_FAIL: bool

    @field_validator("SCAN_TYPE")
    @classmethod
    def validate_scan_type(cls, v):
        if v not in ALLOWED_SCAN_TYPES:
            raise ValueError(f"Invalid SCAN_TYPE. Allowed values: {', '.join(ALLOWED_SCAN_TYPES)}.")
        return v

class IaCScannerConfig(BaseModel):
    REPOSITORY_URL: str
    REPOSITORY_BRANCH: str
    FILE: str
    DIRECTORY: str 
    COMPACT: bool
    QUIET: bool
    FRAMEWORK: Optional[str]

    @field_validator("REPOSITORY_URL", mode="before")
    @classmethod
    def validate_repository_url(cls, v):
        if not v:
            raise ValueError("Unable to retrieve REPOSITORY_URL from Git metadata. Please pass the --repo-url variable.")
        if not isinstance(v, str) or not v.startswith("http"):
            raise ValueError("Invalid REPOSITORY_URL. It must be a valid URL starting with 'http'.")
        return v

    @field_validator("REPOSITORY_BRANCH", mode="before")
    @classmethod
    def validate_repository_branch(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Unable to retrieve REPOSITORY_BRANCH from Git metadata. Please pass the --repo-branch variable")
        return v

class ConfigValidator:
    def __init__(self, scan_type, accuknox_endpoint, accuknox_tenant, accuknox_label, accuknox_token, softfail):
        try:
            self.config = Config(
                SCAN_TYPE=scan_type,
                ACCUKNOX_ENDPOINT=accuknox_endpoint,
                ACCUKNOX_TENANT=accuknox_tenant,
                ACCUKNOX_LABEL=accuknox_label,
                ACCUKNOX_TOKEN=accuknox_token,
                SOFT_FAIL=softfail
            )
        except ValidationError as e:
            for error in e.errors():
                Logger.get_logger().error(f"{error['loc'][0]}: {error['msg']}")
            exit(1)

    def validate_iac_scan(self, repo_url, repo_branch, input_file, input_directory, input_compact, input_quiet, input_framework):
        try:
            self.config = IaCScannerConfig(
                REPOSITORY_URL=repo_url,
                REPOSITORY_BRANCH=repo_branch,
                FILE=input_file,
                DIRECTORY=input_directory,
                COMPACT=input_compact,
                QUIET=input_quiet,
                FRAMEWORK=input_framework
            )
        except ValidationError as e:
            for error in e.errors():
                Logger.get_logger().error(f"{error['loc'][0]}: {error['msg']}")
            exit(1)