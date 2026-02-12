"""
FastAPI Agent Example with PolicyShield enforcement.

Run with:
    uvicorn examples.fastapi_agent.app:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from policyshield.shield import ShieldEngine

# --- Shield Setup ----------------------------------------------------------

RULES_PATH = "examples/fastapi_agent/policies/rules.yaml"

try:
    engine = ShieldEngine(RULES_PATH)
except FileNotFoundError:
    engine = None  # type: ignore[assignment]

# --- FastAPI App -----------------------------------------------------------

app = FastAPI(
    title="PolicyShield FastAPI Agent",
    description="Example agent service with PolicyShield enforcement",
    version="0.5.0",
)


class ToolCallRequest(BaseModel):
    """Request body for a tool call."""

    tool: str
    args: dict = {}
    session_id: str | None = None


class ToolCallResponse(BaseModel):
    """Response body for a tool call verdict."""

    verdict: str
    message: str
    tool: str
    modified_args: dict | None = None


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "shield_active": engine is not None}


@app.post("/evaluate", response_model=ToolCallResponse)
async def evaluate_tool_call(request: ToolCallRequest):
    """Evaluate a tool call against the policy rules."""
    if engine is None:
        raise HTTPException(status_code=503, detail="Shield engine not initialized")

    result = engine.check(request.tool, request.args)

    return ToolCallResponse(
        verdict=result.verdict.value,
        message=result.message or "",
        tool=request.tool,
        modified_args=result.modified_args,
    )


@app.get("/rules")
async def list_rules():
    """List loaded rules."""
    if engine is None:
        raise HTTPException(status_code=503, detail="Shield engine not initialized")

    return {
        "shield_name": engine.ruleset.shield_name,
        "version": engine.ruleset.version,
        "rule_count": len(engine.ruleset.rules),
        "rules": [
            {
                "id": r.id,
                "description": r.description,
                "verdict": r.then,
                "severity": r.severity,
                "enabled": r.enabled,
            }
            for r in engine.ruleset.rules
        ],
    }
