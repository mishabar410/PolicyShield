"""FastAPI application factory for PolicyShield HTTP server."""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from contextlib import asynccontextmanager

import logging

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

from policyshield import __version__

from policyshield.server.models import (
    ApprovalStatusRequest,
    ApprovalStatusResponse,
    CheckRequest,
    CheckResponse,
    ClearTaintRequest,
    ClearTaintResponse,
    ConstraintsResponse,
    HealthResponse,
    KillSwitchResponse,
    PendingApprovalItem,
    PendingApprovalsResponse,
    PostCheckRequest,
    PostCheckResponse,
    ReloadResponse,
    RespondApprovalRequest,
    RespondApprovalResponse,
    ResumeResponse,
    StatusResponse,
)
from policyshield.shield.async_engine import AsyncShieldEngine


def _rules_hash(engine: AsyncShieldEngine) -> str:
    """Compute a stable hash of the current ruleset for change detection."""
    ruleset = engine.rules
    raw = f"{ruleset.shield_name}:{ruleset.version}:{len(ruleset.rules)}"
    for r in ruleset.rules:
        raw += f"|{r.id}:{r.then.value}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _get_api_token() -> str | None:
    """Read API token from environment. Returns None if not configured."""
    return os.environ.get("POLICYSHIELD_API_TOKEN") or None


async def verify_token(request: Request) -> None:
    """Verify Bearer token if POLICYSHIELD_API_TOKEN is set.

    Health endpoint is always public (for Docker/K8s healthchecks).
    When no token is configured, all endpoints are open (dev mode).
    """
    token = _get_api_token()
    if token is None:
        return  # No auth configured — allow all
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    if not hmac.compare_digest(auth_header[7:], token):
        raise HTTPException(status_code=403, detail="Invalid token")


def create_app(engine: AsyncShieldEngine, enable_watcher: bool = False) -> FastAPI:
    """Create a FastAPI application wired to the given AsyncShieldEngine.

    Args:
        engine: A configured AsyncShieldEngine instance.
        enable_watcher: If True, start/stop rule file watcher with the app lifecycle.

    Returns:
        A FastAPI app with /check, /post-check, /health, /constraints, /reload endpoints.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Manage engine watcher lifecycle."""
        if enable_watcher:
            engine.start_watching()
        yield
        if enable_watcher:
            engine.stop_watching()

    app = FastAPI(title="PolicyShield", version=__version__, lifespan=lifespan)

    _logger = logging.getLogger("policyshield.server")

    @app.exception_handler(Exception)
    async def shield_error_handler(request: Request, exc: Exception):
        """Return machine-readable verdict even on internal errors."""
        _logger.error("Unhandled exception in %s: %s", request.url.path, exc, exc_info=True)
        verdict = "ALLOW" if getattr(engine, "_fail_open", False) else "BLOCK"
        return JSONResponse(
            status_code=500,
            content={
                "verdict": verdict,
                "error": "internal_error",
                "message": "Internal server error",
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        """Return clean validation error without leaking internals."""
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "message": "Invalid request format",
            },
        )

    auth = [Depends(verify_token)]

    @app.post("/api/v1/check", response_model=CheckResponse, dependencies=auth)
    async def check(req: CheckRequest) -> CheckResponse:
        req_id = req.request_id or str(uuid.uuid4())
        result = await engine.check(
            tool_name=req.tool_name,
            args=req.args,
            session_id=req.session_id,
            sender=req.sender,
        )
        _logger.info(
            "Check request_id=%s tool=%s verdict=%s",
            req_id,
            req.tool_name,
            result.verdict.value,
        )
        return CheckResponse(
            verdict=result.verdict.value,
            message=result.message,
            rule_id=result.rule_id,
            modified_args=result.modified_args,
            pii_types=[m.pii_type.value for m in result.pii_matches],
            approval_id=result.approval_id,
            shield_version=__version__,
            request_id=req_id,
        )

    @app.post("/api/v1/post-check", response_model=PostCheckResponse, dependencies=auth)
    async def post_check(req: PostCheckRequest) -> PostCheckResponse:
        result = await engine.post_check(
            tool_name=req.tool_name,
            result=req.result,
            session_id=req.session_id,
        )
        return PostCheckResponse(
            pii_types=[m.pii_type.value for m in result.pii_matches],
            redacted_output=result.redacted_output,
        )

    @app.get("/api/v1/constraints", response_model=ConstraintsResponse, dependencies=auth)
    async def constraints() -> ConstraintsResponse:
        return ConstraintsResponse(summary=engine.get_policy_summary())

    @app.get("/api/v1/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        ruleset = engine.rules
        return HealthResponse(
            shield_name=ruleset.shield_name,
            version=ruleset.version,
            rules_count=engine.rule_count,
            mode=engine.mode.value,
            rules_hash=_rules_hash(engine),
        )

    @app.post("/api/v1/reload", response_model=ReloadResponse, dependencies=auth)
    async def reload() -> ReloadResponse:
        """Reload rules from disk."""
        engine.reload_rules()
        return ReloadResponse(
            rules_count=engine.rule_count,
            rules_hash=_rules_hash(engine),
        )

    @app.post("/api/v1/check-approval", response_model=ApprovalStatusResponse, dependencies=auth)
    async def check_approval(req: ApprovalStatusRequest) -> ApprovalStatusResponse:
        """Check the status of a pending approval request."""
        result = engine.get_approval_status(req.approval_id)
        return ApprovalStatusResponse(
            approval_id=req.approval_id,
            status=result["status"],
            responder=result.get("responder"),
        )

    @app.post("/api/v1/clear-taint", response_model=ClearTaintResponse, dependencies=auth)
    async def clear_taint(req: ClearTaintRequest) -> ClearTaintResponse:
        """Clear PII taint from a session, re-enabling outgoing calls."""
        session = engine.session_manager.get(req.session_id)
        if session is not None:
            session.clear_taint()
        return ClearTaintResponse(session_id=req.session_id)

    @app.post("/api/v1/respond-approval", response_model=RespondApprovalResponse, dependencies=auth)
    async def respond_approval(req: RespondApprovalRequest) -> RespondApprovalResponse:
        """Respond to a pending approval request (approve or deny)."""
        backend = engine.approval_backend
        if backend is None:
            raise HTTPException(status_code=500, detail="No approval backend configured")
        backend.respond(
            request_id=req.approval_id,
            approved=req.approved,
            responder=req.responder,
            comment=req.comment,
        )
        return RespondApprovalResponse(approval_id=req.approval_id)

    @app.get("/api/v1/pending-approvals", response_model=PendingApprovalsResponse, dependencies=auth)
    async def pending_approvals() -> PendingApprovalsResponse:
        """List all pending approval requests."""
        backend = engine.approval_backend
        if backend is None:
            return PendingApprovalsResponse()
        pending = backend.pending()
        items = [
            PendingApprovalItem(
                approval_id=r.request_id,
                tool_name=r.tool_name,
                rule_id=r.rule_id,
                message=r.message,
                args=r.args,
            )
            for r in pending
        ]
        return PendingApprovalsResponse(approvals=items)

    # ── Kill switch endpoints ─────────────────────────────────────

    @app.post("/api/v1/kill", response_model=KillSwitchResponse, dependencies=auth)
    async def kill_switch(request: Request) -> KillSwitchResponse:
        """Activate kill switch — block all tool calls."""
        reason = "Kill switch activated via API"
        try:
            body = await request.json()
            if isinstance(body, dict) and "reason" in body:
                reason = body["reason"]
        except Exception:
            pass  # No body or invalid JSON — use default reason
        engine.kill(reason)
        return KillSwitchResponse(status="killed", reason=reason)

    @app.post("/api/v1/resume", response_model=ResumeResponse, dependencies=auth)
    async def resume_switch() -> ResumeResponse:
        """Deactivate kill switch — resume normal operation."""
        engine.resume()
        return ResumeResponse(status="resumed")

    @app.get("/api/v1/status", response_model=StatusResponse, dependencies=auth)
    async def server_status() -> StatusResponse:
        """Get server and engine status."""
        return StatusResponse(
            status="running",
            killed=engine.is_killed,
            mode=engine.mode.value,
            rules_count=engine.rule_count,
            version=__version__,
        )

    return app
