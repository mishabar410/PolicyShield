"""ShieldEngine — synchronous orchestrator for PolicyShield."""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any

from policyshield.core.exceptions import PolicyShieldError
from policyshield.core.models import PostCheckResult, ShieldMode, ShieldResult
from policyshield.shield.base_engine import BaseShieldEngine, logger


class ShieldEngine(BaseShieldEngine):
    """Synchronous orchestrator that coordinates all PolicyShield components.

    Handles pre-call checks (matching + PII), verdict building,
    session updates, and trace recording.  Inherits all shared logic
    from :class:`BaseShieldEngine`.
    """

    def check(
        self,
        tool_name: str,
        args: dict | None = None,
        session_id: str = "default",
        sender: str | None = None,
        context: dict | None = None,
    ) -> ShieldResult:
        """Pre-call check: match rules, detect PII, build verdict.

        Args:
            tool_name: Name of the tool being called.
            args: Arguments to the tool call.
            session_id: Session identifier.
            sender: Identity of the caller.
            context: Optional context dict for context-based conditions.

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
            # Issue #33: Apply timeout to sync check (matches async path)
            if self._engine_timeout and self._engine_timeout > 0:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(
                        self._do_check_sync,
                        tool_name,
                        args,
                        session_id,
                        sender,
                        context,
                    )
                    result = future.result(timeout=self._engine_timeout)
            else:
                result = self._do_check_sync(tool_name, args, session_id, sender, context)
        except concurrent.futures.TimeoutError:
            if self._fail_open:
                logger.warning("Shield check timed out after %ss (fail-open)", self._engine_timeout)
                result = self._verdict_builder.allow()
            else:
                raise PolicyShieldError(f"Shield check timed out after {self._engine_timeout}s")
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

    def post_check(
        self,
        tool_name: str,
        result: Any,
        session_id: str = "default",
    ) -> PostCheckResult:
        """Post-call check on tool output (for PII in results).

        Args:
            tool_name: Name of the tool.
            result: The tool's return value.
            session_id: Session identifier.

        Returns:
            PostCheckResult with PII matches and optional redacted output.
        """
        return self._post_check_sync(tool_name, result, session_id)
