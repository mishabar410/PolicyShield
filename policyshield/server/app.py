"""FastAPI application factory for PolicyShield HTTP server."""

from __future__ import annotations

from fastapi import FastAPI

from policyshield.server.models import (
    CheckRequest,
    CheckResponse,
    ConstraintsResponse,
    HealthResponse,
    PostCheckRequest,
    PostCheckResponse,
)
from policyshield.shield.engine import ShieldEngine


def create_app(engine: ShieldEngine) -> FastAPI:
    """Create a FastAPI application wired to the given ShieldEngine.

    Args:
        engine: A configured ShieldEngine instance.

    Returns:
        A FastAPI app with /check, /post-check, /health, /constraints endpoints.
    """
    app = FastAPI(title="PolicyShield", version="1.0.0")

    @app.post("/api/v1/check", response_model=CheckResponse)
    async def check(req: CheckRequest) -> CheckResponse:
        result = engine.check(
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
        )

    @app.post("/api/v1/post-check", response_model=PostCheckResponse)
    async def post_check(req: PostCheckRequest) -> PostCheckResponse:
        result = engine.post_check(
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
        )

    return app
