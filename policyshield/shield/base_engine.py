"""BaseShieldEngine — shared logic for sync and async engines."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from policyshield.approval.base import ApprovalBackend, ApprovalRequest
from policyshield.approval.cache import ApprovalCache, ApprovalStrategy
from policyshield.core.models import (
    RuleSet,
    ShieldMode,
    ShieldResult,
    Verdict,
)
from policyshield.core.parser import load_rules
from policyshield.shield.matcher import MatcherEngine
from policyshield.shield.pii import PIIDetector
from policyshield.shield.session import SessionManager
from policyshield.shield.verdict import VerdictBuilder
from policyshield.trace.recorder import TraceRecorder

logger = logging.getLogger("policyshield")


class BaseShieldEngine:
    """Base orchestrator with all shared PolicyShield logic.

    Subclasses (:class:`ShieldEngine`, :class:`AsyncShieldEngine`) provide
    sync / async ``check()`` and ``post_check()`` entry points.
    """

    def __init__(
        self,
        rules: RuleSet | str | Path,
        mode: ShieldMode = ShieldMode.ENFORCE,
        pii_detector: PIIDetector | None = None,
        session_manager: SessionManager | None = None,
        trace_recorder: TraceRecorder | None = None,
        rate_limiter: object | None = None,
        approval_backend: ApprovalBackend | None = None,
        approval_timeout: float = 300.0,
        approval_cache: ApprovalCache | None = None,
        fail_open: bool = True,
        otel_exporter: object | None = None,
        sanitizer: object | None = None,
    ):
        """Initialize engine components.

        Args:
            rules: RuleSet object, or path to YAML file/directory.
            mode: Operating mode (ENFORCE, AUDIT, DISABLED).
            pii_detector: Optional PII detector instance.
            session_manager: Optional session manager instance.
            trace_recorder: Optional trace recorder instance.
            rate_limiter: Optional RateLimiter instance.
            approval_backend: Optional approval backend for APPROVE verdicts.
            approval_timeout: Seconds to wait for approval response.
            approval_cache: Optional approval cache for batch strategies.
            fail_open: If True, errors in shield don't block tool calls.
            otel_exporter: Optional OTelExporter for OpenTelemetry integration.
            sanitizer: Optional InputSanitizer for arg sanitization.
        """
        if isinstance(rules, (str, Path)):
            self._rule_set = load_rules(rules)
            self._rules_path: Path | None = Path(rules)
        else:
            self._rule_set = rules
            self._rules_path = None

        self._mode = mode
        self._matcher = MatcherEngine(self._rule_set)
        self._pii = pii_detector or PIIDetector()
        self._session_mgr = session_manager or SessionManager()
        self._verdict_builder = VerdictBuilder()
        self._tracer = trace_recorder
        self._rate_limiter = rate_limiter
        self._approval_backend = approval_backend
        self._approval_timeout = approval_timeout
        self._approval_cache = approval_cache
        self._fail_open = fail_open
        self._otel = otel_exporter
        self._sanitizer = sanitizer
        self._lock = threading.Lock()
        self._watcher = None

    # ------------------------------------------------------------------ #
    #  Core check logic (sync)                                           #
    # ------------------------------------------------------------------ #

    def _build_session_state(self, session_id: str) -> dict:
        """Build the session-state dict used for condition matching."""
        session = self._session_mgr.get_or_create(session_id)
        state: dict[str, Any] = {
            "total_calls": session.total_calls,
            "tool_counts": dict(session.tool_counts),
            "taints": [t.value for t in session.taints],
        }
        for tool, count in session.tool_counts.items():
            state[f"tool_count.{tool}"] = count
        return state

    def _do_check_sync(
        self,
        tool_name: str,
        args: dict,
        session_id: str,
        sender: str | None,
    ) -> ShieldResult:
        """Synchronous check logic: sanitize → rate-limit → match → PII → verdict."""
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

        # Find best matching rule
        match = self._matcher.find_best_match(
            tool_name=tool_name,
            args=args,
            session_state=session_state,
            sender=sender,
        )

        if match is None:
            return self._verdict_builder.allow(args=args)

        rule = match.rule

        # PII detection on args
        pii_matches = []
        try:
            pii_matches = self._pii.scan_dict(args)
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
            redacted, scan_matches = self._pii.redact_dict(args)
            all_pii = pii_matches if pii_matches else scan_matches
            return self._verdict_builder.redact(
                rule=rule,
                tool_name=tool_name,
                args=args,
                modified_args=redacted,
                pii_matches=all_pii,
            )
        elif rule.then == Verdict.APPROVE:
            return self._handle_approval_sync(rule, tool_name, args, session_id)
        else:
            return self._verdict_builder.allow(rule=rule, args=args)

    def _handle_approval_sync(
        self,
        rule: Any,
        tool_name: str,
        args: dict,
        session_id: str,
    ) -> ShieldResult:
        """Handle APPROVE verdict synchronously."""
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
        self._approval_backend.submit(req)
        resp = self._approval_backend.wait_for_response(req.request_id, timeout=self._approval_timeout)
        if resp is None:
            return ShieldResult(
                verdict=Verdict.BLOCK,
                rule_id=rule.id,
                message="Approval timed out",
            )

        # Cache the response
        if self._approval_cache is not None:
            self._approval_cache.put(tool_name, rule.id, session_id, resp, strategy=strategy)

        if resp.approved:
            return self._verdict_builder.allow(rule=rule, args=args)
        return ShieldResult(
            verdict=Verdict.BLOCK,
            rule_id=rule.id,
            message=f"Approval denied by {resp.responder}" if resp.responder else "Approval denied",
        )

    # ------------------------------------------------------------------ #
    #  Shared helpers                                                     #
    # ------------------------------------------------------------------ #

    def _apply_post_check(
        self, result: ShieldResult, session_id: str, tool_name: str, latency_ms: float, args: dict
    ) -> ShieldResult:
        """Apply audit-mode override, session update, and trace after a check."""
        # In AUDIT mode, always allow but record the would-be verdict
        if self._mode == ShieldMode.AUDIT and result.verdict != Verdict.ALLOW:
            logger.info("AUDIT: would %s %s (rule=%s)", result.verdict.value, tool_name, result.rule_id)
            audit_result = ShieldResult(
                verdict=Verdict.ALLOW,
                rule_id=result.rule_id,
                message=f"[AUDIT] {result.message}",
                pii_matches=result.pii_matches,
                original_args=result.original_args,
                modified_args=result.modified_args,
            )
            self._trace(audit_result, session_id, tool_name, latency_ms, args)
            return audit_result

        # Update session & rate-limit only when the tool will actually execute
        if result.verdict not in (Verdict.BLOCK, Verdict.APPROVE):
            self._session_mgr.increment(session_id, tool_name)
            if self._rate_limiter is not None:
                self._rate_limiter.record(tool_name, session_id)

        # Record trace
        self._trace(result, session_id, tool_name, latency_ms, args)
        return result

    def _trace(
        self,
        result: ShieldResult,
        session_id: str,
        tool_name: str,
        latency_ms: float,
        args: dict | None = None,
    ) -> None:
        """Record a trace entry if tracer is configured."""
        if not self._tracer:
            return
        pii_types = [m.pii_type.value for m in result.pii_matches]
        self._tracer.record(
            session_id=session_id,
            tool=tool_name,
            verdict=result.verdict,
            rule_id=result.rule_id,
            pii_types=pii_types,
            latency_ms=latency_ms,
            args=args,
        )

    def _post_check_sync(
        self,
        tool_name: str,
        result: Any,
        session_id: str = "default",
    ) -> ShieldResult:
        """Post-call check on tool output (PII scan on results)."""
        if self._mode == ShieldMode.DISABLED:
            return self._verdict_builder.allow()

        pii_matches: list = []

        if isinstance(result, str):
            pii_matches = self._pii.scan(result)
        elif isinstance(result, dict):
            pii_matches = self._pii.scan_dict(result)

        for pm in pii_matches:
            self._session_mgr.add_taint(session_id, pm.pii_type)

        return ShieldResult(
            verdict=Verdict.ALLOW,
            pii_matches=pii_matches,
        )

    # ------------------------------------------------------------------ #
    #  Rule management                                                    #
    # ------------------------------------------------------------------ #

    def reload_rules(self, path: str | Path | None = None) -> None:
        """Reload rules from a new path (thread-safe).

        Args:
            path: Path to YAML file or directory. If None, reloads from original path.
        """
        reload_path = Path(path) if path else self._rules_path
        if reload_path is None:
            logger.warning("reload_rules called but no path available")
            return
        new_ruleset = load_rules(reload_path)
        with self._lock:
            self._rule_set = new_ruleset
            self._matcher = MatcherEngine(self._rule_set)
        logger.info("Rules reloaded from %s (%d rules)", reload_path, len(new_ruleset.rules))

    def start_watching(self, poll_interval: float = 2.0) -> None:
        """Start watching YAML files for hot reload.

        Args:
            poll_interval: Seconds between checks.
        """
        if self._rules_path is None:
            logger.warning("Cannot watch: engine was created with a RuleSet, not a path")
            return
        from policyshield.shield.watcher import RuleWatcher

        self._watcher = RuleWatcher(
            self._rules_path,
            callback=self._hot_reload_callback,
            poll_interval=poll_interval,
        )
        self._watcher.start()

    def stop_watching(self) -> None:
        """Stop watching files."""
        if self._watcher:
            self._watcher.stop()
            self._watcher = None

    def _hot_reload_callback(self, new_ruleset: RuleSet) -> None:
        """Callback for the watcher to swap rules."""
        with self._lock:
            self._rule_set = new_ruleset
            self._matcher = MatcherEngine(new_ruleset)
        logger.info("Hot-reloaded %d rules", len(new_ruleset.rules))

    # ------------------------------------------------------------------ #
    #  Properties                                                         #
    # ------------------------------------------------------------------ #

    @property
    def mode(self) -> ShieldMode:
        """Return current operating mode."""
        return self._mode

    @mode.setter
    def mode(self, value: ShieldMode) -> None:
        """Set operating mode."""
        self._mode = value

    @property
    def rule_count(self) -> int:
        """Return number of active rules."""
        with self._lock:
            return self._matcher.rule_count

    @property
    def rules(self) -> RuleSet:
        """Return current rule set (thread-safe)."""
        with self._lock:
            return self._rule_set
