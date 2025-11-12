import os
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator, FieldValidationInfo
from typing import Optional, Literal
from aspm_cli.utils.logger import Logger
from aspm_cli.utils.common import ALLOWED_SCAN_TYPES

def _format_validation_error(e: ValidationError) -> str:
    """Return a concise error summary (no verbose Pydantic metadata)."""
    errors = []
    for err in e.errors():
        loc = " → ".join(str(x) for x in err.get("loc", []))
        msg = err.get("msg", "")
        errors.append(f"{loc}: {msg}")
    return "; ".join(errors)

class AccuknoxConfig(BaseModel):
    accuknox_endpoint: Optional[str] = Field(None, env="ACCUKNOX_ENDPOINT", description="AccuKnox API endpoint")
    accuknox_label: Optional[str] = Field(None, env="ACCUKNOX_LABEL", description="AccuKnox label for scan results")
    accuknox_token: Optional[str] = Field(None, env="ACCUKNOX_TOKEN", description="AccuKnox authentication token")
    skip_upload: bool = Field(False) 
    accuknox_tenant: Optional[int]

    @model_validator(mode='after') 
    def check_env_vars_and_upload_requirements(self) -> 'AccuknoxConfig':
        # Check env vars (equivalent to root_validator(pre=True) for env vars)
        if self.accuknox_endpoint is None and "ACCUKNOX_ENDPOINT" in os.environ:
            self.accuknox_endpoint = os.environ["ACCUKNOX_ENDPOINT"]
        if self.accuknox_label is None and "ACCUKNOX_LABEL" in os.environ:
            self.accuknox_label = os.environ["ACCUKNOX_LABEL"]
        if self.accuknox_token is None and "ACCUKNOX_TOKEN" in os.environ:
            self.accuknox_token = os.environ["ACCUKNOX_TOKEN"]

        # Check required for upload (equivalent to V1 validator for multiple fields)
        if not self.skip_upload:
            if self.accuknox_endpoint is None:
                raise ValueError(
                    f"Accuknox Endpoint is required for uploading scan results. "
                    f"Either provide it via CLI argument or set the 'ACCUKNOX_ENDPOINT' environment variable, "
                    "or use '--skip-upload' if you don't want to upload results."
                )
            if self.accuknox_label is None:
                raise ValueError(
                    f"Accuknox Label is required for uploading scan results. "
                    f"Either provide it via CLI argument or set the 'ACCUKNOX_LABEL' environment variable, "
                    "or use '--skip-upload' if you don't want to upload results."
                )
            if self.accuknox_token is None:
                raise ValueError(
                    f"Accuknox Token is required for uploading scan results. "
                    f"Either provide it via CLI argument or set the 'ACCUKNOX_TOKEN' environment variable, "
                    "or use '--skip-upload' if you don't want to upload results."
                )
        return self


    class Config:
        env_prefix = 'ACCUKNOX_'
        extra = 'forbid' # Ensure only defined fields are accepted


class ConfigValidator:
    def __init__(self, scantype: str, softfail: bool, skip_upload: bool, **kwargs):
        self.scantype = scantype.upper()
        self.softfail = softfail
        self.skip_upload = skip_upload

        # Validate general AccuKnox configurations first
        try:
            # Pass kwargs directly; AccuknoxConfig now handles 'skip_upload'
            self.accuknox_config = AccuknoxConfig(skip_upload=skip_upload, **kwargs)
        except ValidationError as e:
            concise_msg = _format_validation_error(e)
            Logger.get_logger().debug(f"AccuKnox configuration error: {concise_msg}")
            raise ValueError(concise_msg)

        Logger.get_logger().debug(f"Initialized ConfigValidator for scantype: {self.scantype}, softfail: {self.softfail}, skip_upload: {self.skip_upload}")


    def _log_validation_success(self, scan_name: str):
        Logger.get_logger().info(f"{scan_name} scan configuration validated successfully.")

    # --- Scan-specific validations ---
    # These methods encapsulate the validation rules for each scan type.
    # They leverage Pydantic models internally for strong validation.

    def validate_iac_scan(self, command: str, container_mode: bool, repo_url: Optional[str], repo_branch: Optional[str]):
        class IaCScanConfig(BaseModel):
            command: str = Field(..., min_length=1, description="Command arguments for IAC scanner")
            container_mode: bool
            repo_url: Optional[str]
            repo_branch: Optional[str]

        try:
            IaCScanConfig(command=command, container_mode=container_mode, repo_url=repo_url, repo_branch=repo_branch)
            self._log_validation_success("IAC")
        except ValidationError as e:
            concise_msg = _format_validation_error(e)
            Logger.get_logger().debug(f"IAC scan configuration error: {concise_msg}")
            raise ValueError(concise_msg)

    def validate_sq_sast_scan(self, skip_sonar_scan: bool, command: str, container_mode: bool, repo_url: Optional[str], branch: Optional[str], commit_sha: Optional[str], pipeline_url: Optional[str]):
        class SQSAScanConfig(BaseModel):
            skip_sonar_scan: bool
            command: str = Field(..., min_length=1, description="Command arguments for SQ SAST scanner")
            container_mode: bool
            repo_url: Optional[str]
            branch: Optional[str]
            commit_sha: Optional[str]
            pipeline_url: Optional[str]

            @model_validator(mode='after')
            def check_sonar_command_if_not_skipped(self) -> 'SQSAScanConfig':
                if not self.skip_sonar_scan and not self.command:
                    raise ValueError("Command is required for SQ SAST scan if not skipping SonarQube scan.")
                return self

        try:
            SQSAScanConfig(
                skip_sonar_scan=skip_sonar_scan,
                command=command,
                container_mode=container_mode,
                repo_url=repo_url,
                branch=branch,
                commit_sha=commit_sha,
                pipeline_url=pipeline_url
            )
            self._log_validation_success("SQ SAST")
        except ValidationError as e:
            concise_msg = _format_validation_error(e)
            Logger.get_logger().debug(f"SQ SAST scan configuration error: {concise_msg}")
            raise ValueError(concise_msg)

    def validate_secret_scan(self, command: str, container_mode: bool):
        class SecretScanConfig(BaseModel):
            command: str = Field(..., min_length=1, description="Command arguments for Secret scanner")
            container_mode: bool

        try:
            SecretScanConfig(command=command, container_mode=container_mode)
            self._log_validation_success("Secret")
        except ValidationError as e:
            concise_msg = _format_validation_error(e)
            Logger.get_logger().debug(f"Secret scan configuration error: {concise_msg}")
            raise ValueError(concise_msg)

    def validate_container_scan(self, command: str, container_mode: bool):
        class ContainerScanConfig(BaseModel):
            command: str = Field(..., min_length=1, description="Command arguments for Container scanner")
            container_mode: bool

        try:
            ContainerScanConfig(command=command, container_mode=container_mode)
            self._log_validation_success("Container")
        except ValidationError as e:
            concise_msg = _format_validation_error(e)
            Logger.get_logger().debug(f"Container scan configuration error: {concise_msg}")
            raise ValueError(concise_msg)

    def validate_sast_scan(self, command: str, container_mode: bool, severity: str, repo_url: Optional[str], commit_ref: Optional[str], commit_sha: Optional[str], pipeline_id: Optional[str], job_url: Optional[str]):
        class SASTScanConfig(BaseModel):
            command: str = Field(..., min_length=1, description="Command arguments for SAST scanner")
            container_mode: bool
            severity: str = Field(..., description="Comma-separated list of severities")
            repo_url: Optional[str]
            commit_ref: Optional[str]
            commit_sha: Optional[str]
            pipeline_id: Optional[str]
            job_url: Optional[str]
            
            @field_validator("severity", mode="before")
            @classmethod
            def validate_severity(cls, v: str, info: FieldValidationInfo):
                allowed_severities = {"INFO", "WARNING", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                if not isinstance(v, str):
                    raise ValueError("Severity must be a comma-separated string.")

                provided_severities = {s.strip().upper() for s in v.split(",") if s.strip()}

                if not provided_severities:
                    raise ValueError("At least one severity must be provided.")

                invalid = provided_severities - allowed_severities
                if invalid:
                    raise ValueError(
                        f"Invalid severity values: {', '.join(sorted(invalid))}. "
                        f"Allowed values: {', '.join(sorted(allowed_severities))}."
                )
                return ",".join(sorted(provided_severities))

        try:
            SASTScanConfig(
                command=command,
                container_mode=container_mode,
                severity=severity,
                repo_url=repo_url,
                commit_ref=commit_ref,
                commit_sha=commit_sha,
                pipeline_id=pipeline_id,
                job_url=job_url
            )
            self._log_validation_success("SAST")
        except ValidationError as e:
            concise_msg = _format_validation_error(e)
            Logger.get_logger().debug(f"SAST scan configuration error: {concise_msg}")
            raise ValueError(concise_msg)

    def validate_dast_scan(self, command: str, severity_threshold: str, container_mode: bool):
        class DASTScanConfig(BaseModel):
            command: str = Field(..., min_length=1, description="Command arguments for DAST scanner")
            severity_threshold: Literal["LOW", "MEDIUM", "HIGH"] = Field(..., description="Severity threshold for DAST scan")
            container_mode: bool

            @field_validator("severity_threshold", mode="before")
            @classmethod
            def convert_to_upper(cls, v: str):
                return v.upper()

        try:
            DASTScanConfig(command=command, severity_threshold=severity_threshold, container_mode=container_mode)
            self._log_validation_success("DAST")
        except ValidationError as e:
            concise_msg = _format_validation_error(e)
            Logger.get_logger().debug(f"DAST scan configuration error: {concise_msg}")
            raise ValueError(concise_msg)