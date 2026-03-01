"""Pydantic models for PolicyShield HTTP server request/response payloads."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


def _check_depth(obj: object, max_depth: int = 10, current: int = 0) -> None:
    """Reject deeply nested structures (bomb prevention)."""
    if current > max_depth:
        raise ValueError(f"Nesting exceeds max depth ({max_depth})")
    if isinstance(obj, dict):
        for val in obj.values():
            _check_depth(val, max_depth, current + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_depth(item, max_depth, current + 1)


class CheckRequest(BaseModel):
    """Request body for the /api/v1/check endpoint."""

    tool_name: str = Field(..., min_length=1, max_length=256, pattern=r"^[\w.\-:]+$")
    args: dict = {}
    session_id: str = Field(default="default", min_length=1, max_length=256)
    sender: str | None = Field(default=None, max_length=256)
    request_id: str | None = Field(default=None, max_length=128)
    context: dict | None = Field(default=None, description="Optional context for context-based rule conditions")

    @field_validator("args")
    @classmethod
    def validate_args_depth(cls, v: dict) -> dict:
        _check_depth(v)
        return v


class CheckResponse(BaseModel):
    """Response body for the /api/v1/check endpoint."""

    verdict: str  # "ALLOW" | "BLOCK" | "REDACT" | "APPROVE"
    message: str = ""
    rule_id: str | None = None
    modified_args: dict | None = None
    pii_types: list[str] = []
    approval_id: str | None = None
    shield_version: str = ""
    request_id: str = ""


class PostCheckRequest(BaseModel):
    """Request body for the /api/v1/post-check endpoint."""

    tool_name: str = Field(..., min_length=1, max_length=256, pattern=r"^[\w.\-:]+$")
    args: dict = {}
    result: str = Field(default="", max_length=1_000_000)
    session_id: str = Field(default="default", min_length=1, max_length=256)


class PostCheckResponse(BaseModel):
    """Response body for the /api/v1/post-check endpoint."""

    pii_types: list[str] = []
    redacted_output: str | None = None


class ConstraintsResponse(BaseModel):
    """Response body for the /api/v1/constraints endpoint."""

    summary: str


class HealthResponse(BaseModel):
    """Response body for the /api/v1/health endpoint."""

    status: str = "ok"
    shield_name: str = ""
    version: int = 0
    rules_count: int = 0
    mode: str = ""
    rules_hash: str = ""


class ReloadResponse(BaseModel):
    """Response body for the /api/v1/reload endpoint."""

    status: str = "ok"
    rules_count: int = 0
    rules_hash: str = ""


class ApprovalStatusRequest(BaseModel):
    """Request body for the /api/v1/check-approval endpoint."""

    approval_id: str


class ApprovalStatusResponse(BaseModel):
    """Response body for the /api/v1/check-approval endpoint."""

    approval_id: str
    status: str  # "pending" | "approved" | "denied"
    responder: str | None = None


class ClearTaintRequest(BaseModel):
    """Request body for the /api/v1/clear-taint endpoint."""

    session_id: str


class ClearTaintResponse(BaseModel):
    """Response body for the /api/v1/clear-taint endpoint."""

    status: str = "ok"
    session_id: str


class RespondApprovalRequest(BaseModel):
    """Request body for the /api/v1/respond-approval endpoint."""

    approval_id: str
    approved: bool
    responder: str = ""
    comment: str = ""


class RespondApprovalResponse(BaseModel):
    """Response body for the /api/v1/respond-approval endpoint."""

    status: str = "ok"
    approval_id: str


class PendingApprovalItem(BaseModel):
    """Single pending approval in the list."""

    approval_id: str
    tool_name: str
    rule_id: str
    message: str
    args: dict = {}


class PendingApprovalsResponse(BaseModel):
    """Response body for the /api/v1/pending-approvals endpoint."""

    approvals: list[PendingApprovalItem] = []


class KillSwitchRequest(BaseModel):
    """Request body for the /api/v1/kill endpoint."""

    reason: str = "Kill switch activated via API"


class KillSwitchResponse(BaseModel):
    """Response body for the /api/v1/kill endpoint."""

    status: str = "killed"
    reason: str = ""


class ResumeResponse(BaseModel):
    """Response body for the /api/v1/resume endpoint."""

    status: str = "resumed"


class StatusResponse(BaseModel):
    """Response body for the /api/v1/status endpoint."""

    status: str = "running"
    killed: bool = False
    mode: str = ""
    rules_count: int = 0
    version: str = ""


class CompileRequest(BaseModel):
    """Request body for the /api/v1/compile endpoint."""

    description: str = Field(..., min_length=1, max_length=2000)


class CompileResponse(BaseModel):
    """Response body for the /api/v1/compile endpoint."""

    yaml_text: str = ""
    is_valid: bool = False
    errors: list[str] = []


class CompileAndApplyResponse(BaseModel):
    """Response body for the /api/v1/compile-and-apply endpoint."""

    yaml_text: str = ""
    is_valid: bool = False
    errors: list[str] = []
    applied: bool = False
    rules_count: int = 0


