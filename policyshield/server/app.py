"""FastAPI application factory for PolicyShield HTTP server."""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager

from fastapi import FastAPI

from policyshield import __version__

from policyshield.server.models import (
    ApprovalStatusRequest,
    ApprovalStatusResponse,
    CheckRequest,
    CheckResponse,
    ConstraintsResponse,
    HealthResponse,
    PostCheckRequest,
    PostCheckResponse,
    ReloadResponse,
)
from policyshield.shield.async_engine import AsyncShieldEngine


def _rules_hash(engine: AsyncShieldEngine) -> str:
    """Compute a stable hash of the current ruleset for change detection."""
    ruleset = engine.rules
    raw = f"{ruleset.shield_name}:{ruleset.version}:{len(ruleset.rules)}"
    for r in ruleset.rules:
        raw += f"|{r.id}:{r.then.value}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


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

    @app.post("/api/v1/check", response_model=CheckResponse)
    async def check(req: CheckRequest) -> CheckResponse:
        result = await engine.check(
            tool_name=req.tool_name,
            args=req.args,
            session_id=req.session_id,
            sender=req.sender,
        )
        return CheckResponse(
            verdict=result.verdict.value,
            message=result.message,
            rule_id=result.rule_id,
            modified_args=result.modified_args,
            pii_types=[m.pii_type.value for m in result.pii_matches],
            approval_id=result.approval_id,
        )

    @app.post("/api/v1/post-check", response_model=PostCheckResponse)
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

    @app.get("/api/v1/constraints", response_model=ConstraintsResponse)
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

    @app.post("/api/v1/reload", response_model=ReloadResponse)
    async def reload() -> ReloadResponse:
        """Reload rules from disk."""
        engine.reload_rules()
        return ReloadResponse(
            rules_count=engine.rule_count,
            rules_hash=_rules_hash(engine),
        )

    @app.post("/api/v1/check-approval", response_model=ApprovalStatusResponse)
    async def check_approval(req: ApprovalStatusRequest) -> ApprovalStatusResponse:
        """Check the status of a pending approval request."""
        result = engine.get_approval_status(req.approval_id)
        return ApprovalStatusResponse(
            approval_id=req.approval_id,
            status=result["status"],
            responder=result.get("responder"),
        )

    return app
