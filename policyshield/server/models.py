"""Pydantic models for PolicyShield HTTP server request/response payloads."""

from __future__ import annotations

from pydantic import BaseModel


class CheckRequest(BaseModel):
    """Request body for the /api/v1/check endpoint."""

    tool_name: str
    args: dict = {}
    session_id: str = "default"
    sender: str | None = None


class CheckResponse(BaseModel):
    """Response body for the /api/v1/check endpoint."""

    verdict: str  # "ALLOW" | "BLOCK" | "REDACT" | "APPROVE"
    message: str = ""
    rule_id: str | None = None
    modified_args: dict | None = None
    pii_types: list[str] = []
    approval_id: str | None = None


class PostCheckRequest(BaseModel):
    """Request body for the /api/v1/post-check endpoint."""

    tool_name: str
    args: dict = {}
    result: str = ""
    session_id: str = "default"


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

