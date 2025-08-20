from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from typing import Optional
from aspm_cli.utils.logger import Logger
import sys

ALLOWED_SCAN_TYPES = {"iac", "sast", "sq-sast", "secret", "container", "dast"}
ALLOWED_TOOL_TYPES = {"iac", "sq-sast", "secret", "container"}

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

class ContainerScannerConfig(BaseModel):
    COMMAND: str
    CONTAINER_MODE: bool

class IaCScannerConfig(BaseModel):
    REPOSITORY_URL: str
    REPOSITORY_BRANCH: str
    COMMAND: str
    CONTAINER_MODE: bool

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

class DASTScannerConfig(BaseModel):
    SEVERITY_THRESHOLD: str
    COMMAND: str
    CONTAINER_MODE: bool

    @field_validator("SEVERITY_THRESHOLD", mode="before")
    @classmethod
    def validate_severity_threshold(cls, v):
        allowed = {"HIGH", "MEDIUM", "LOW"}
        if v and v.upper() not in allowed:
            raise ValueError(f"Invalid SEVERITY_THRESHOLD '{v}'. Allowed values: {', '.join(allowed)}.")
        return v

class SASTScannerConfig(BaseModel):
    REPOSITORY_URL: str
    COMMIT_REF: str
    COMMIT_SHA: str
    PIPELINE_ID: Optional[str] 
    JOB_URL: Optional[str]

    @field_validator("REPOSITORY_URL", mode="before")
    @classmethod
    def validate_repository_url(cls, v):
        if not v:
            raise ValueError("Unable to retrieve REPOSITORY_URL from Git metadata. Please pass the --repo-url variable.")
        if not isinstance(v, str) or not v.startswith("http"):
            raise ValueError("Invalid REPOSITORY_URL. It must be a valid URL starting with 'http'.")
        return v

    @field_validator("COMMIT_REF", mode="before")
    @classmethod
    def validate_commit_ref(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Unable to retrieve COMMIT_REF from Git metadata. Please pass the --commit-ref variable")
        return v
    
    @field_validator("COMMIT_SHA", mode="before")
    @classmethod
    def validate_commit_sha(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Unable to retrieve COMMIT_SHA from Git metadata. Please pass the --commit-sha variable")
        return v
    
class SQSASTScannerConfig(BaseModel):
    COMMAND: str
    SKIP_SONAR_SCAN: bool
    CONTAINER_MODE: bool
    
    REPOSITORY_URL: str
    BRANCH: str
    COMMIT_SHA: str
    PIPELINE_URL: Optional[str] 

    @field_validator("REPOSITORY_URL", mode="before")
    @classmethod
    def validate_repository_url(cls, v):
        if not v:
            raise ValueError("Unable to retrieve REPOSITORY_URL from Git metadata. Please pass the --repo-url variable.")
        if not isinstance(v, str) or not v.startswith("http"):
            raise ValueError("Invalid REPOSITORY_URL. It must be a valid URL starting with 'http'.")
        return v

    @field_validator("BRANCH", mode="before")
    @classmethod
    def validate_commit_ref(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Unable to retrieve BRANCH from Git metadata. Please pass the --branch variable")
        return v
    
    @field_validator("COMMIT_SHA", mode="before")
    @classmethod
    def validate_commit_sha(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError("Unable to retrieve COMMIT_SHA from Git metadata. Please pass the --commit-sha variable")
        return v

class SecretScannerConfig(BaseModel):
    COMMAND: str
    CONTAINER_MODE: bool

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
            sys.exit(1)

    def validate_iac_scan(self, command, container_mode, repo_url, repo_branch):
        try:
            self.config = IaCScannerConfig(
                COMMAND=command,
                CONTAINER_MODE=container_mode,
                REPOSITORY_URL=repo_url,
                REPOSITORY_BRANCH=repo_branch
            )
        except ValidationError as e:
            for error in e.errors():
                Logger.get_logger().error(f"{error['loc'][0]}: {error['msg']}")
            sys.exit(1)

    def validate_sast_scan(self, repo_url, commit_ref, commit_sha, pipeline_id, job_url):
        try:
            self.config = SASTScannerConfig(
                REPOSITORY_URL=repo_url,
                COMMIT_REF=commit_ref,
                COMMIT_SHA=commit_sha,
                PIPELINE_ID=pipeline_id,
                JOB_URL=job_url
            )
        except ValidationError as e:
            for error in e.errors():
                Logger.get_logger().error(f"{error['loc'][0]}: {error['msg']}")
            sys.exit(1)


    def validate_sq_sast_scan(self, skip_sonar_scan, command,  container_mode, repo_url, branch, commit_sha, pipeline_url):
        try:
            self.config = SQSASTScannerConfig(
                COMMAND=command,
                CONTAINER_MODE=container_mode,
                SKIP_SONAR_SCAN=skip_sonar_scan,
                REPOSITORY_URL=repo_url,
                BRANCH=branch,
                COMMIT_SHA=commit_sha,
                PIPELINE_URL=pipeline_url,
            )
        except ValidationError as e:
            for error in e.errors():
                Logger.get_logger().error(f"{error['loc'][0]}: {error['msg']}")
            sys.exit(1)

    def validate_secret_scan(self, command, container_mode):
        try:
            self.config = SecretScannerConfig(
                COMMAND=command,
                CONTAINER_MODE=container_mode,
            )
        except ValidationError as e:
            for error in e.errors():
                Logger.get_logger().error(f"{error['loc'][0]}: {error['msg']}")
            sys.exit(1)

    def validate_container_scan(self, command,  container_mode):
        try:
            self.config = ContainerScannerConfig(
                COMMAND=command,
                CONTAINER_MODE=container_mode,
            )
        except ValidationError as e:
            for error in e.errors():
                Logger.get_logger().error(f"{error['loc'][0]}: {error['msg']}")
            sys.exit(1)

    def validate_dast_scan(self, command, severity_threshold, container_mode):
        try:
            self.config = DASTScannerConfig(
                SEVERITY_THRESHOLD=severity_threshold,
                COMMAND=command,
                CONTAINER_MODE=container_mode,
            )
        except ValidationError as e:
            for error in e.errors():
                Logger.get_logger().error(f"{error['loc'][0]}: {error['msg']}")
            sys.exit(1)