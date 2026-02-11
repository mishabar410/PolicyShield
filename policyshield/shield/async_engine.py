"""AsyncShieldEngine — fully async orchestrator for PolicyShield."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from policyshield.approval.base import ApprovalRequest
from policyshield.approval.cache import ApprovalStrategy
from policyshield.core.exceptions import PolicyShieldError
from policyshield.core.models import ShieldMode, ShieldResult, Verdict
from policyshield.shield.base_engine import BaseShieldEngine, logger


class AsyncShieldEngine(BaseShieldEngine):
    """Async orchestrator that coordinates all PolicyShield components.

    Provides async/await versions of :class:`ShieldEngine` methods for
    integration with FastAPI, aiohttp, async LangChain agents, and CrewAI.
    CPU-bound work (matching, PII regex) is offloaded via
    ``asyncio.to_thread`` to avoid blocking the event loop.

    Inherits all shared logic from :class:`BaseShieldEngine`.
    """

    async def check(
        self,
        tool_name: str,
        args: dict | None = None,
        session_id: str = "default",
        sender: str | None = None,
    ) -> ShieldResult:
        """Async pre-call check: match rules, detect PII, build verdict.

        Args:
            tool_name: Name of the tool being called.
            args: Arguments to the tool call.
            session_id: Session identifier.
            sender: Identity of the caller.

        Returns:
            ShieldResult with the verdict and details.
        """
        if self._mode == ShieldMode.DISABLED:
            return self._verdict_builder.allow()

        start = time.monotonic()
        args = args or {}

        # OTel: start span
        span_ctx = None
        if self._otel:
            span_ctx = self._otel.on_check_start(tool_name, session_id, args)

        try:
            result = await self._do_check(tool_name, args, session_id, sender)
        except Exception as e:
            if self._fail_open:
                logger.warning("Shield error (fail-open): %s", e)
                result = self._verdict_builder.allow()
            else:
                raise PolicyShieldError(f"Shield check failed: {e}") from e

        latency_ms = (time.monotonic() - start) * 1000

        # OTel: end span
        if self._otel:
            self._otel.on_check_end(span_ctx, result, latency_ms)

        return self._apply_post_check(result, session_id, tool_name, latency_ms, args)

    async def _do_check(
        self,
        tool_name: str,
        args: dict,
        session_id: str,
        sender: str | None,
    ) -> ShieldResult:
        """Internal check logic — offloads CPU-bound work to threads."""
        # Sanitize args
        if self._sanitizer is not None:
            san_result = self._sanitizer.sanitize(args)
            if san_result.rejected:
                return ShieldResult(
                    verdict=Verdict.BLOCK,
                    rule_id="__sanitizer__",
                    message=san_result.rejection_reason,
                )
            args = san_result.sanitized_args

        # Rate limit check
        if self._rate_limiter is not None:
            rl_result = self._rate_limiter.check(tool_name, session_id)
            if not rl_result.allowed:
                return ShieldResult(
                    verdict=Verdict.BLOCK,
                    rule_id="__rate_limit__",
                    message=rl_result.message,
                )

        # Session state for condition matching
        session_state = self._build_session_state(session_id)

        # Offload CPU-bound matching to thread
        match = await asyncio.to_thread(
            self._matcher.find_best_match,
            tool_name=tool_name,
            args=args,
            session_state=session_state,
            sender=sender,
        )

        if match is None:
            return self._verdict_builder.allow(args=args)

        rule = match.rule

        # PII detection (CPU-bound regex) — offload to thread
        pii_matches = []
        try:
            pii_matches = await asyncio.to_thread(self._pii.scan_dict, args)
        except Exception as e:
            logger.warning("PII detection error (fail-open): %s", e)

        # Taint session with detected PII types
        for pm in pii_matches:
            self._session_mgr.add_taint(session_id, pm.pii_type)

        # Build verdict based on rule
        if rule.then == Verdict.BLOCK:
            return self._verdict_builder.block(
                rule=rule,
                tool_name=tool_name,
                args=args,
                pii_matches=pii_matches,
            )
        elif rule.then == Verdict.REDACT:
            redacted, scan_matches = await asyncio.to_thread(
                self._pii.redact_dict, args
            )
            all_pii = pii_matches if pii_matches else scan_matches
            return self._verdict_builder.redact(
                rule=rule,
                tool_name=tool_name,
                args=args,
                modified_args=redacted,
                pii_matches=all_pii,
            )
        elif rule.then == Verdict.APPROVE:
            return await self._handle_approval(rule, tool_name, args, session_id)
        else:
            return self._verdict_builder.allow(rule=rule, args=args)

    async def _handle_approval(
        self,
        rule: Any,
        tool_name: str,
        args: dict,
        session_id: str,
    ) -> ShieldResult:
        """Handle APPROVE verdict with async support."""
        if self._approval_backend is None:
            return ShieldResult(
                verdict=Verdict.BLOCK,
                rule_id=rule.id,
                message="No approval backend configured",
            )

        # Determine strategy
        strategy = None
        if rule.approval_strategy:
            try:
                strategy = ApprovalStrategy(rule.approval_strategy)
            except ValueError:
                pass

        # Check cache first
        if self._approval_cache is not None:
            cached = self._approval_cache.get(
                tool_name, rule.id, session_id, strategy=strategy
            )
            if cached is not None:
                if cached.approved:
                    return self._verdict_builder.allow(rule=rule, args=args)
                return ShieldResult(
                    verdict=Verdict.BLOCK,
                    rule_id=rule.id,
                    message="Approval denied (cached)",
                )

        req = ApprovalRequest.create(
            tool_name=tool_name,
            args=args,
            rule_id=rule.id,
            message=rule.message or "Approval required",
            session_id=session_id,
        )

        # Offload sync approval backend to thread
        await asyncio.to_thread(self._approval_backend.submit, req)
        resp = await asyncio.to_thread(
            self._approval_backend.wait_for_response,
            req.request_id,
            timeout=self._approval_timeout,
        )

        if resp is None:
            return ShieldResult(
                verdict=Verdict.BLOCK,
                rule_id=rule.id,
                message="Approval timed out",
            )

        # Cache the response
        if self._approval_cache is not None:
            self._approval_cache.put(
                tool_name, rule.id, session_id, resp, strategy=strategy
            )

        if resp.approved:
            return self._verdict_builder.allow(rule=rule, args=args)
        return ShieldResult(
            verdict=Verdict.BLOCK,
            rule_id=rule.id,
            message=(
                f"Approval denied by {resp.responder}"
                if resp.responder
                else "Approval denied"
            ),
        )

    async def post_check(
        self,
        tool_name: str,
        result: Any,
        session_id: str = "default",
    ) -> ShieldResult:
        """Async post-call check on tool output (for PII in results).

        Args:
            tool_name: Name of the tool.
            result: The tool's return value.
            session_id: Session identifier.

        Returns:
            ShieldResult (currently always ALLOW).
        """
        if self._mode == ShieldMode.DISABLED:
            return self._verdict_builder.allow()

        if isinstance(result, dict):
            pii_matches = await asyncio.to_thread(self._pii.scan_dict, result)
            for pm in pii_matches:
                self._session_mgr.add_taint(session_id, pm.pii_type)

        return self._verdict_builder.allow()
