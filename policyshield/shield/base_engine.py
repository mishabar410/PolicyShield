"""BaseShieldEngine — shared logic for sync and async engines."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from time import monotonic
from typing import Any

from policyshield.approval.base import ApprovalBackend, ApprovalRequest
from policyshield.approval.cache import ApprovalCache, ApprovalStrategy
from policyshield.core.models import (
    PostCheckResult,
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
        self._approval_cache = approval_cache
        self._fail_open = fail_open
        self._otel = otel_exporter
        self._sanitizer = sanitizer
        self._lock = threading.Lock()
        self._watcher = None
        # Approval metadata for cache population after resolution
        self._approval_meta: dict[str, dict] = {}
        self._approval_meta_ts: dict[str, float] = {}
        self._approval_meta_ttl: float = 3600.0  # 1 hour
        self._max_approval_meta: int = 10_000
        # Resolved approval statuses for idempotent polling
        self._resolved_approvals: dict[str, dict] = {}
        self._max_resolved_approvals = 10_000

        # Kill switch — atomic, lock-free via threading.Event
        self._killed = threading.Event()  # Not set = normal operation
        self._kill_reason: str = ""

        # Honeypot checker (load from ruleset)
        honeypot_config = self._rule_set.honeypots
        if honeypot_config:
            from policyshield.shield.honeypots import HoneypotChecker

            self._honeypot_checker: object | None = HoneypotChecker.from_config(honeypot_config)
        else:
            self._honeypot_checker = None

        # Taint chain config
        tc = self._rule_set.taint_chain
        self._taint_enabled: bool = tc.enabled
        self._outgoing_tools: set[str] = set(tc.outgoing_tools)

    # ------------------------------------------------------------------ #
    #  Kill switch                                                       #
    # ------------------------------------------------------------------ #

    def kill(self, reason: str = "Kill switch activated") -> None:
        """Activate kill switch — block ALL tool calls immediately.

        Args:
            reason: Human-readable reason for the kill switch activation.
        """
        self._kill_reason = reason
        self._killed.set()

    def resume(self) -> None:
        """Deactivate kill switch — resume normal operation."""
        self._killed.clear()
        self._kill_reason = ""

    @property
    def is_killed(self) -> bool:
        """Whether kill switch is active."""
        return self._killed.is_set()

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
        """Synchronous check logic: kill_switch → sanitize → rate-limit → taint → match → PII → verdict."""
        # Kill switch — absolute first check, overrides everything
        if self._killed.is_set():
            return ShieldResult(
                verdict=Verdict.BLOCK,
                rule_id="__kill_switch__",
                message=self._kill_reason or "Kill switch activated",
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

        # Rate limit check
        if self._rate_limiter is not None:
            rl_result = self._rate_limiter.check(tool_name, session_id)
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

        # Find best matching rule
        try:
            # Pass event buffer for chain rule evaluation
            event_buffer = self._session_mgr.get_event_buffer(session_id)
            match = matcher.find_best_match(
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
                pii_matches = self._pii.scan_dict(args)
            except Exception as e:
                logger.warning("PII detection error (fail-open): %s", e)
            # Taint session with detected PII types
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
            redacted, pii_matches = self._pii.redact_dict(args)
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

    def _cleanup_approval_meta(self) -> None:
        """Remove stale and excess entries from _approval_meta (caller holds lock)."""
        now = monotonic()
        # TTL cleanup
        expired = [k for k, ts in self._approval_meta_ts.items() if now - ts > self._approval_meta_ttl]
        for k in expired:
            self._approval_meta.pop(k, None)
            self._approval_meta_ts.pop(k, None)

        # Hard limit (evict oldest)
        while len(self._approval_meta) > self._max_approval_meta:
            oldest = min(self._approval_meta_ts, key=self._approval_meta_ts.get)  # type: ignore[arg-type]
            self._approval_meta.pop(oldest, None)
            self._approval_meta_ts.pop(oldest, None)

    def get_approval_status(self, approval_id: str) -> dict:
        """Check the status of a pending approval request.

        Returns:
            dict with 'status' ('pending', 'approved', 'denied') and optional 'responder'.
        """
        with self._lock:
            # Return cached result for idempotent polling
            if approval_id in self._resolved_approvals:
                return self._resolved_approvals[approval_id]

        if self._approval_backend is None:
            return {"status": "denied", "responder": None}

        resp = self._approval_backend.wait_for_response(approval_id, timeout=0.0)
        if resp is None:
            return {"status": "pending", "responder": None}

        # Build and cache the resolved status
        if resp.approved:
            result = {"status": "approved", "responder": resp.responder}
        else:
            result = {"status": "denied", "responder": resp.responder}

        with self._lock:
            # Evict oldest entries if cache is full
            if len(self._resolved_approvals) >= self._max_resolved_approvals:
                to_remove = list(self._resolved_approvals.keys())[: len(self._resolved_approvals) // 4]
                for k in to_remove:
                    del self._resolved_approvals[k]
            self._resolved_approvals[approval_id] = result

            # Populate approval cache for batch strategies
            if self._approval_cache is not None and approval_id in self._approval_meta:
                meta = self._approval_meta.pop(approval_id)
                self._approval_cache.put(
                    tool_name=meta["tool_name"],
                    rule_id=meta["rule_id"],
                    session_id=meta["session_id"],
                    response=resp,
                    strategy=meta["strategy"],
                )

        return result

    # ------------------------------------------------------------------ #
    #  Shared helpers                                                     #
    # ------------------------------------------------------------------ #

    def _apply_post_check(
        self, result: ShieldResult, session_id: str, tool_name: str, latency_ms: float, args: dict
    ) -> ShieldResult:
        """Apply audit-mode override, session update, and trace after a check."""
        # In AUDIT mode, always allow but record the would-be verdict
        # Exception: kill switch and honeypots override even AUDIT mode
        if (
            self._mode == ShieldMode.AUDIT
            and result.verdict != Verdict.ALLOW
            and result.rule_id not in ("__kill_switch__", "__honeypot__")
        ):
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

        # Record event in ring buffer for chain rule tracking
        buf = self._session_mgr.get_event_buffer(session_id)
        buf.add(tool_name, result.verdict.value)

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
    ) -> PostCheckResult:
        """Post-call check on tool output (PII scan on results)."""
        if self._mode == ShieldMode.DISABLED:
            return PostCheckResult()

        pii_matches: list = []
        redacted_output: str | None = None

        if isinstance(result, str):
            pii_matches = self._pii.scan(result)
            if pii_matches:
                redacted_output = self._pii.redact_text(result)
        elif isinstance(result, dict):
            pii_matches = self._pii.scan_dict(result)
            if pii_matches:
                redacted_dict, _ = self._pii.redact_dict(result)
                redacted_output = str(redacted_dict)

        tainted = False
        for pm in pii_matches:
            self._session_mgr.add_taint(session_id, pm.pii_type)
            tainted = True

        # Set PII taint on session if taint chain is enabled
        if tainted and self._taint_enabled:
            session = self._session_mgr.get_or_create(session_id)
            pii_types = ", ".join(m.pii_type.value for m in pii_matches)
            session.set_taint(f"PII detected in {tool_name} output: {pii_types}")
            logger.warning(
                "Session %s tainted: PII (%s) in %s output",
                session_id,
                pii_types,
                tool_name,
            )

        return PostCheckResult(
            pii_matches=pii_matches,
            redacted_output=redacted_output,
            session_tainted=tainted,
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
            # Refresh honeypot checker from reloaded rules
            honeypot_config = new_ruleset.honeypots
            if honeypot_config:
                from policyshield.shield.honeypots import HoneypotChecker

                self._honeypot_checker = HoneypotChecker.from_config(honeypot_config)
            else:
                self._honeypot_checker = None
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
            # Refresh honeypot checker from reloaded rules
            honeypot_config = new_ruleset.honeypots
            if honeypot_config:
                from policyshield.shield.honeypots import HoneypotChecker

                self._honeypot_checker = HoneypotChecker.from_config(honeypot_config)
            else:
                self._honeypot_checker = None
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

    @property
    def session_manager(self) -> SessionManager:
        """Return the session manager."""
        return self._session_mgr

    @property
    def approval_backend(self):
        """Return the approval backend (or None if not configured)."""
        return self._approval_backend

    def get_policy_summary(self) -> str:
        """Return human-readable summary of active rules for LLM context."""
        lines = [f"PolicyShield: {self._rule_set.shield_name} v{self._rule_set.version}"]
        lines.append(f"Default: {self._rule_set.default_verdict.value}")
        lines.append(f"Rules: {len(self._rule_set.rules)}")
        for rule in self._rule_set.rules:
            lines.append(f"  - [{rule.then.value}] {rule.id}: {rule.message or rule.description or rule.id}")
        return "\n".join(lines)
