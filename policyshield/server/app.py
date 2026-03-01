"""FastAPI application factory for PolicyShield HTTP server."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import uuid
from contextlib import asynccontextmanager

import logging

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from policyshield import __version__
from policyshield.server.idempotency import IdempotencyCache
from policyshield.server.metrics import MetricsCollector

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
    Admin endpoints (/reload, /kill-switch) require ADMIN_TOKEN if set.
    When no token is configured, all endpoints are open (dev mode).
    """
    api_token = _get_api_token()
    admin_token = os.environ.get("POLICYSHIELD_ADMIN_TOKEN") or None

    admin_paths = ("/api/v1/reload", "/api/v1/kill")
    is_admin = any(request.url.path.startswith(p) for p in admin_paths)

    if is_admin:
        required = admin_token or api_token  # Fallback to API token
    else:
        required = api_token

    if required is None:
        return  # No auth configured
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    if not hmac.compare_digest(auth_header[7:], required):
        raise HTTPException(status_code=403, detail="Invalid token")


def create_app(engine: AsyncShieldEngine, enable_watcher: bool = False) -> FastAPI:
    """Create a FastAPI application wired to the given AsyncShieldEngine.

    Args:
        engine: A configured AsyncShieldEngine instance.
        enable_watcher: If True, start/stop rule file watcher with the app lifecycle.

    Returns:
        A FastAPI app with /check, /post-check, /health, /constraints, /reload endpoints.
    """

    _shutting_down = asyncio.Event()

    async def _startup_self_test() -> None:
        """Run a quick self-test to verify engine is operational."""
        try:
            result = await engine.check("__self_test__", {})
            _logger.info("Startup self-test passed: verdict=%s", result.verdict.value)
        except Exception as e:
            _logger.critical("Startup self-test FAILED: %s", e)
            raise RuntimeError(f"Engine self-test failed: {e}") from e

    _logger = logging.getLogger("policyshield.server")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Manage engine lifecycle: self-test on startup, drain on shutdown."""
        if enable_watcher:
            engine.start_watching()
        await _startup_self_test()
        yield
        # Graceful shutdown
        _shutting_down.set()
        _logger.info("Shutting down — draining in-flight requests...")
        await asyncio.sleep(1)  # Brief drain window
        if engine._tracer:
            engine._tracer.flush()
        if (
            hasattr(engine, "_approval_backend")
            and engine._approval_backend
            and hasattr(engine._approval_backend, "stop")
        ):
            engine._approval_backend.stop()
        if enable_watcher:
            engine.stop_watching()
        _logger.info("PolicyShield server stopped")

    app = FastAPI(
        title="PolicyShield",
        version=__version__,
        description="Declarative firewall for AI agent tool calls",
        lifespan=lifespan,
        openapi_tags=[
            {"name": "check", "description": "Tool call validation endpoints"},
            {"name": "admin", "description": "Kill switch, reload, approval management"},
            {"name": "observability", "description": "Health, metrics, readiness probes"},
        ],
    )

    # CORS middleware (env config, disabled by default)
    cors_origins = os.environ.get("POLICYSHIELD_CORS_ORIGINS", "").split(",")
    cors_origins = [o.strip() for o in cors_origins if o.strip()]
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
            max_age=3600,
        )

    # ── Middleware: Reject new requests during shutdown (331) ──
    _shutdown_allowed_paths = {"/api/v1/health", "/healthz", "/readyz", "/metrics"}

    @app.middleware("http")
    async def reject_during_shutdown(request: Request, call_next):
        if _shutting_down.is_set() and request.url.path not in _shutdown_allowed_paths:
            return JSONResponse(
                status_code=503,
                content={"error": "shutting_down", "verdict": "BLOCK"},
            )
        return await call_next(request)

    # Only validate Content-Type on endpoints that strictly expect JSON bodies
    _json_only_paths = {
        "/api/v1/check",
        "/api/v1/post-check",
        "/api/v1/check-approval",
        "/api/v1/clear-taint",
        "/api/v1/respond-approval",
    }

    @app.middleware("http")
    async def content_type_check(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            if request.url.path in _json_only_paths:
                ct = request.headers.get("content-type", "")
                if ct and "application/json" not in ct:
                    return JSONResponse(
                        status_code=415,
                        content={
                            "error": "unsupported_media_type",
                            "expected": "application/json",
                        },
                    )
        return await call_next(request)

    # ── Middleware: Payload size limit (305) ──
    _max_request_size = int(os.environ.get("POLICYSHIELD_MAX_REQUEST_SIZE", 1_048_576))

    @app.middleware("http")
    async def payload_size_limit(request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            # Quick reject by header
            content_length = request.headers.get("content-length")
            try:
                cl_int = int(content_length) if content_length else 0
            except (ValueError, TypeError):
                cl_int = 0
            if cl_int > _max_request_size:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "payload_too_large",
                        "message": f"Request body exceeds {_max_request_size} bytes",
                        "max_bytes": _max_request_size,
                    },
                )
            # Only verify actual body size when Content-Length is missing/untrusted
            # (Content-Length can be spoofed or absent with chunked encoding)
            if not content_length or cl_int == 0:
                body = await request.body()
                if len(body) > _max_request_size:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "payload_too_large",
                            "message": f"Request body exceeds {_max_request_size} bytes",
                            "max_bytes": _max_request_size,
                        },
                    )
        return await call_next(request)

    # ── Middleware: Backpressure (307) ──
    _max_concurrent = int(os.environ.get("POLICYSHIELD_MAX_CONCURRENT_CHECKS", 100))
    _semaphore = asyncio.Semaphore(_max_concurrent)

    @app.middleware("http")
    async def backpressure_middleware(request: Request, call_next):
        if request.url.path in ("/api/v1/check", "/api/v1/post-check", "/api/v1/check-approval"):
            try:
                # Atomic try-acquire with tiny timeout (no TOCTOU race)
                await asyncio.wait_for(_semaphore.acquire(), timeout=0.01)
            except asyncio.TimeoutError:
                return JSONResponse(
                    status_code=503,
                    content={
                        "verdict": "BLOCK",
                        "error": "server_overloaded",
                        "message": "Too many concurrent requests",
                    },
                )
            try:
                return await call_next(request)
            finally:
                _semaphore.release()
        return await call_next(request)

    # ── Middleware: Request timeout (308) ──
    _request_timeout = float(os.environ.get("POLICYSHIELD_REQUEST_TIMEOUT", 30))

    @app.middleware("http")
    async def timeout_middleware(request: Request, call_next):
        # NOTE: asyncio.wait_for wraps the initial response construction only.
        # For streaming responses, the timeout does NOT cover the body streaming
        # phase. Use per-endpoint timeouts for streaming endpoints.
        if request.url.path.startswith("/api/"):
            try:
                return await asyncio.wait_for(call_next(request), timeout=_request_timeout)
            except asyncio.TimeoutError:
                _logger.error(
                    "Request timeout (%.1fs) for %s",
                    _request_timeout,
                    request.url.path,
                )
                return JSONResponse(
                    status_code=504,
                    content={
                        "verdict": "BLOCK",
                        "error": "request_timeout",
                        "message": f"Request exceeded {_request_timeout}s",
                    },
                )
        return await call_next(request)

    # ── Middleware: Admin rate limiting (326) ──
    from policyshield.server.rate_limiter import InMemoryRateLimiter as _AdminRL

    _admin_limiter = _AdminRL(max_requests=10, window_seconds=60)

    @app.middleware("http")
    async def rate_limit_admin(request: Request, call_next):
        admin_paths = ("/api/v1/reload", "/api/v1/kill")
        if any(request.url.path.startswith(p) for p in admin_paths):
            client_ip = request.client.host if request.client else "unknown"
            if not request.client:
                _logger.warning("Admin rate-limit: request.client is None (proxy misconfiguration?)")
            if not _admin_limiter.is_allowed(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate_limited", "message": "Too many requests"},
                )
        return await call_next(request)

    # ── Middleware: API rate limiting (406) ──
    from policyshield.server.rate_limiter import APIRateLimiter as _APIRL

    _api_rate_limit = int(os.environ.get("POLICYSHIELD_API_RATE_LIMIT", "100"))
    _api_rate_window = float(os.environ.get("POLICYSHIELD_API_RATE_WINDOW", "60"))
    _api_limiter = _APIRL(max_requests=_api_rate_limit, window_seconds=_api_rate_window)

    @app.middleware("http")
    async def api_rate_limit(request: Request, call_next):
        check_paths = ("/api/v1/check", "/api/v1/post-check")
        if request.url.path in check_paths:
            client_key = request.client.host if request.client else "unknown"
            if not request.client:
                _logger.warning("API rate-limit: request.client is None (proxy misconfiguration?)")
            # Use hash of API token as key if available (prevents prefix-rotation bypass)
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer ") and len(auth) > 7:
                import hashlib
                client_key = f"token:{hashlib.sha256(auth[7:].encode()).hexdigest()[:16]}"
            if not _api_limiter.is_allowed(client_key):
                return JSONResponse(
                    status_code=429,
                    content={
                        "verdict": "BLOCK",
                        "error": "rate_limited",
                        "message": f"Rate limit exceeded ({_api_rate_limit}/{_api_rate_window}s)",
                    },
                    headers={"Retry-After": str(int(_api_rate_window))},
                )
        return await call_next(request)

    # ── Debug mode (323) ──
    _debug = os.environ.get("POLICYSHIELD_DEBUG", "").lower() in ("1", "true", "yes")

    @app.exception_handler(Exception)
    async def shield_error_handler(request: Request, exc: Exception):
        """Return machine-readable verdict even on internal errors."""
        _logger.error("Unhandled exception in %s: %s", request.url.path, exc, exc_info=True)
        verdict = "ALLOW" if getattr(engine, "_fail_open", False) else "BLOCK"
        detail: dict = {
            "verdict": verdict,
            "error": "internal_error",
            "message": "Internal server error",
        }
        if _debug:
            detail["debug"] = {"type": type(exc).__name__, "detail": str(exc)}
        return JSONResponse(status_code=500, content=detail)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        """Return clean validation error without leaking internals."""
        detail: dict = {
            "error": "validation_error",
            "message": "Invalid request format",
        }
        if _debug:
            detail["debug"] = {"errors": exc.errors()}
        return JSONResponse(status_code=422, content=detail)

    auth = [Depends(verify_token)]

    _idem_cache = IdempotencyCache()

    @app.post("/api/v1/check", response_model=CheckResponse, dependencies=auth)
    async def check(req: CheckRequest, request: Request) -> CheckResponse:
        req_id = req.request_id or str(uuid.uuid4())
        # Idempotency key support
        idem_key = request.headers.get("x-idempotency-key")
        if idem_key:
            cached = _idem_cache.get(idem_key)
            if cached:
                return CheckResponse(**cached)
        result = await engine.check(
            tool_name=req.tool_name,
            args=req.args,
            session_id=req.session_id,
            sender=req.sender,
            context=req.context,
        )
        _logger.info(
            "Check request_id=%s tool=%s verdict=%s",
            req_id,
            req.tool_name,
            result.verdict.value,
        )
        response = CheckResponse(
            verdict=result.verdict.value,
            message=result.message,
            rule_id=result.rule_id,
            modified_args=result.modified_args,
            pii_types=[m.pii_type.value for m in result.pii_matches],
            approval_id=result.approval_id,
            shield_version=__version__,
            request_id=req_id,
        )
        if idem_key:
            _idem_cache.set(idem_key, response.model_dump())
        return response

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

    # K8s probes (no auth required)
    @app.get("/healthz")
    async def liveness():
        """Kubernetes liveness probe — always OK if process is running."""
        return {"status": "alive"}

    @app.get("/readyz")
    async def readiness():
        """Kubernetes readiness probe — OK if engine is loaded and not shutting down."""
        if _shutting_down.is_set():
            return JSONResponse(status_code=503, content={"status": "shutting_down"})
        if engine.rule_count == 0:
            return JSONResponse(status_code=503, content={"status": "no_rules_loaded"})

        result: dict = {"status": "ready", "rules": engine.rule_count}
        # Check approval backend health
        backend = engine.approval_backend
        if backend is not None:
            health = backend.health()
            result["approval_backend"] = health
            if not health["healthy"]:
                return JSONResponse(
                    status_code=503,
                    content={**result, "status": "approval_backend_unhealthy"},
                )
        return result

    # Aliases under /api/v1/ prefix for consistency
    @app.get("/api/v1/livez")
    async def api_livez():
        return await liveness()

    @app.get("/api/v1/readyz")
    async def api_readyz():
        return await readiness()

    _metrics_collector = MetricsCollector()

    @app.get("/metrics")
    async def metrics():
        """Prometheus-format metrics endpoint."""
        from starlette.responses import PlainTextResponse as _PT

        return _PT(_metrics_collector.to_prometheus(), media_type="text/plain")

    @app.post("/api/v1/reload", response_model=ReloadResponse, dependencies=auth)
    async def reload() -> ReloadResponse:
        """Reload rules from disk."""
        engine.reload_rules()
        return ReloadResponse(
            rules_count=engine.rule_count,
            rules_hash=_rules_hash(engine),
        )

    # ── Approval poll timeout (316) ──
    _approval_poll_timeout = float(os.environ.get("POLICYSHIELD_APPROVAL_POLL_TIMEOUT", 30))

    @app.post("/api/v1/check-approval", response_model=ApprovalStatusResponse, dependencies=auth)
    async def check_approval(req: ApprovalStatusRequest) -> ApprovalStatusResponse:
        """Check the status of a pending approval request."""
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(engine.get_approval_status, req.approval_id),
                timeout=_approval_poll_timeout,
            )
        except asyncio.TimeoutError:
            return ApprovalStatusResponse(approval_id=req.approval_id, status="timeout")
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
        from policyshield.approval.sanitizer import sanitize_args

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
                args=sanitize_args(r.args),
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
