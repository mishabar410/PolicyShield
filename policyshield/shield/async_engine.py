"""AsyncShieldEngine — fully async orchestrator for PolicyShield.

Note: ``_do_check`` intentionally duplicates most of
``BaseShieldEngine._do_check_sync`` with ``await asyncio.to_thread()``
wrappers.  Any logic change in the sync path must be mirrored here.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from policyshield.approval.base import ApprovalRequest
from policyshield.approval.cache import ApprovalStrategy
from policyshield.core.exceptions import PolicyShieldError
from time import monotonic

from policyshield.core.models import PostCheckResult, ShieldMode, ShieldResult, Verdict
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
            result = await asyncio.wait_for(
                self._do_check(tool_name, args, session_id, sender),
                timeout=self._engine_timeout,
            )
        except asyncio.TimeoutError:
            logger.error(
                "Engine check timeout (%.1fs) for tool=%s",
                self._engine_timeout,
                tool_name,
            )
            verdict = Verdict.ALLOW if self._fail_open else Verdict.BLOCK
            result = ShieldResult(verdict=verdict, message="Check timed out")
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
        # Kill switch — immediate block
        if self._killed.is_set():
            return ShieldResult(
                verdict=Verdict.BLOCK,
                rule_id="__kill_switch__",
                message=self._kill_reason or "Kill switch is active",
            )

        # Honeypot check — always block, regardless of mode
        if self._honeypot_checker is not None:
            honeypot_match = self._honeypot_checker.check(tool_name)
            if honeypot_match:
                return ShieldResult(
                    verdict=Verdict.BLOCK,
                    rule_id="__honeypot__",
                    message=honeypot_match.message,
                )

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

        # Plugin detectors (mirror _do_check_sync)
        from policyshield.plugins import DetectorResult as _DR
        from policyshield.plugins import get_detectors as _get_detectors

        for pname, detector_fn in _get_detectors().items():
            try:
                det_result = await asyncio.to_thread(detector_fn, tool_name=tool_name, args=args)
                if isinstance(det_result, _DR) and det_result.detected:
                    logger.warning("Plugin detector '%s' triggered: %s", pname, det_result.message)
                    return ShieldResult(
                        verdict=Verdict.BLOCK,
                        rule_id=f"__plugin__{pname}",
                        message=det_result.message,
                    )
            except Exception as e:
                logger.warning("Plugin detector '%s' error: %s", pname, e)

        # Rate limit check (atomic check + record)
        if self._rate_limiter is not None:
            rl_result = self._rate_limiter.check_and_record(tool_name, session_id)
            if not rl_result.allowed:
                return ShieldResult(
                    verdict=Verdict.BLOCK,
                    rule_id="__rate_limit__",
                    message=rl_result.message,
                )

        # PII taint chain — block outgoing calls if session is tainted
        if self._taint_enabled and tool_name in self._outgoing_tools:
            session = self._session_mgr.get_or_create(session_id)
            if session.pii_tainted:
                return ShieldResult(
                    verdict=Verdict.BLOCK,
                    rule_id="__pii_taint__",
                    message=(f"Session tainted: {session.taint_details}. Outgoing calls blocked until reviewed."),
                )

        # Session state for condition matching
        session_state = self._build_session_state(session_id)

        # Snapshot matcher + rule_set atomically to avoid race with hot-reload
        with self._lock:
            matcher = self._matcher
            rule_set = self._rule_set

        # Offload CPU-bound matching to thread
        try:
            # Pass event buffer for chain rule evaluation
            event_buffer = self._session_mgr.get_event_buffer(session_id)
            match = await asyncio.to_thread(
                matcher.find_best_match,
                tool_name=tool_name,
                args=args,
                session_state=session_state,
                sender=sender,
                event_buffer=event_buffer,
            )
        except Exception as e:
            logger.error("Matcher error: %s", e)
            if self._fail_open:
                return self._verdict_builder.allow(args=args)
            return ShieldResult(
                verdict=Verdict.BLOCK,
                rule_id="__error__",
                message=f"Internal error: {e}",
            )

        if match is None:
            default = rule_set.default_verdict
            if default == Verdict.BLOCK:
                return ShieldResult(
                    verdict=Verdict.BLOCK,
                    rule_id="__default__",
                    message="No matching rule. Default policy: BLOCK.",
                )
            return self._verdict_builder.allow(args=args)

        rule = match.rule

        # Build verdict based on rule
        if rule.then == Verdict.BLOCK:
            # PII detection on args (only for BLOCK to enrich the message)
            pii_matches = []
            try:
                pii_matches = await asyncio.to_thread(self._pii.scan_dict, args)
            except Exception as e:
                logger.warning("PII detection error (fail-open): %s", e)
            for pm in pii_matches:
                self._session_mgr.add_taint(session_id, pm.pii_type)

            return self._verdict_builder.block(
                rule=rule,
                tool_name=tool_name,
                args=args,
                pii_matches=pii_matches,
            )
        elif rule.then == Verdict.REDACT:
            # redact_dict scans for PII internally — no need for a separate scan
            redacted, pii_matches = await asyncio.to_thread(self._pii.redact_dict, args)
            for pm in pii_matches:
                self._session_mgr.add_taint(session_id, pm.pii_type)
            return self._verdict_builder.redact(
                rule=rule,
                tool_name=tool_name,
                args=args,
                modified_args=redacted,
                pii_matches=pii_matches,
            )
        elif rule.then == Verdict.APPROVE:
            result = await self._handle_approval(rule, tool_name, args, session_id)
        else:
            result = self._verdict_builder.allow(rule=rule, args=args)

        # Shadow evaluation (non-blocking, log-only) — mirrors _do_check_sync
        with self._lock:
            shadow_matcher = self._shadow_matcher

        if shadow_matcher is not None:
            try:
                shadow_match = await asyncio.to_thread(
                    shadow_matcher.find_best_match,
                    tool_name=tool_name,
                    args=args,
                    session_state=session_state,
                    sender=sender,
                    event_buffer=event_buffer,
                )
                shadow_verdict = shadow_match.rule.then if shadow_match else Verdict.ALLOW
                if shadow_match and shadow_match.rule.then != result.verdict:
                    logger.info(
                        "SHADOW: tool=%s verdict_diff: current=%s shadow=%s (rule=%s)",
                        tool_name,
                        result.verdict.value,
                        shadow_verdict.value,
                        shadow_match.rule.id,
                    )
                if self._tracer:
                    self._tracer.record(
                        session_id=session_id,
                        tool=tool_name,
                        verdict=shadow_verdict if shadow_match else Verdict.ALLOW,
                        rule_id=f"__shadow__{shadow_match.rule.id}" if shadow_match else "__shadow__",
                    )
            except Exception as e:
                logger.warning("Shadow evaluation error: %s", e)

        return result

    async def _handle_approval(
        self,
        rule: Any,
        tool_name: str,
        args: dict,
        session_id: str,
    ) -> ShieldResult:
        """Handle APPROVE verdict with async support.

        Returns immediately with the approval_id so the caller can poll
        /check-approval for status (non-blocking pattern).
        """
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
            cached = self._approval_cache.get(tool_name, rule.id, session_id, strategy=strategy)
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

        # Offload sync approval backend submit to thread
        await asyncio.to_thread(self._approval_backend.submit, req)

        # Store metadata for cache population after resolution
        with self._lock:
            self._approval_meta[req.request_id] = {
                "tool_name": tool_name,
                "rule_id": rule.id,
                "session_id": session_id,
                "strategy": strategy,
            }
            self._approval_meta_ts[req.request_id] = monotonic()
            self._cleanup_approval_meta()

        # Return APPROVE verdict with the approval_id for async polling
        return ShieldResult(
            verdict=Verdict.APPROVE,
            rule_id=rule.id,
            message=rule.message or "Approval required",
            approval_id=req.request_id,
        )

    async def post_check(
        self,
        tool_name: str,
        result: Any,
        session_id: str = "default",
    ) -> PostCheckResult:
        """Async post-call check on tool output (for PII in results).

        Args:
            tool_name: Name of the tool.
            result: The tool's return value.
            session_id: Session identifier.

        Returns:
            PostCheckResult with PII matches and optional redacted output.
        """
        return await asyncio.to_thread(self._post_check_sync, tool_name, result, session_id)
