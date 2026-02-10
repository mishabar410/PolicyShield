"""ShieldEngine — the central orchestrator for PolicyShield."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from policyshield.core.exceptions import PolicyShieldError
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


class ShieldEngine:
    """Central orchestrator that coordinates all PolicyShield components.

    Handles pre-call checks (matching + PII), verdict building,
    session updates, and trace recording.
    """

    def __init__(
        self,
        rules: RuleSet | str | Path,
        mode: ShieldMode = ShieldMode.ENFORCE,
        pii_detector: PIIDetector | None = None,
        session_manager: SessionManager | None = None,
        trace_recorder: TraceRecorder | None = None,
        fail_open: bool = True,
    ):
        """Initialize ShieldEngine.

        Args:
            rules: RuleSet object, or path to YAML file/directory.
            mode: Operating mode (ENFORCE, AUDIT, DISABLED).
            pii_detector: Optional PII detector instance.
            session_manager: Optional session manager instance.
            trace_recorder: Optional trace recorder instance.
            fail_open: If True, errors in shield don't block tool calls.
        """
        # Load rules
        if isinstance(rules, (str, Path)):
            self._rule_set = load_rules(rules)
        else:
            self._rule_set = rules

        self._mode = mode
        self._matcher = MatcherEngine(self._rule_set)
        self._pii = pii_detector or PIIDetector()
        self._session_mgr = session_manager or SessionManager()
        self._verdict_builder = VerdictBuilder()
        self._tracer = trace_recorder
        self._fail_open = fail_open

    def check(
        self,
        tool_name: str,
        args: dict | None = None,
        session_id: str = "default",
        sender: str | None = None,
    ) -> ShieldResult:
        """Pre-call check: match rules, detect PII, build verdict.

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

        try:
            result = self._do_check(tool_name, args, session_id, sender)
        except Exception as e:
            if self._fail_open:
                logger.warning("Shield error (fail-open): %s", e)
                result = self._verdict_builder.allow()
            else:
                raise PolicyShieldError(f"Shield check failed: {e}") from e

        latency_ms = (time.monotonic() - start) * 1000

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

        # Update session
        self._session_mgr.increment(session_id, tool_name)

        # Record trace
        self._trace(result, session_id, tool_name, latency_ms, args)

        return result

    def _do_check(
        self,
        tool_name: str,
        args: dict,
        session_id: str,
        sender: str | None,
    ) -> ShieldResult:
        """Internal check logic."""
        # Get session state for condition matching
        session = self._session_mgr.get_or_create(session_id)
        session_state = {
            "total_calls": session.total_calls,
            "tool_counts": dict(session.tool_counts),
            "taints": [t.value for t in session.taints],
        }
        # Flatten tool_counts for dot-notation access (e.g. tool_count.web_fetch)
        for tool, count in session.tool_counts.items():
            session_state[f"tool_count.{tool}"] = count

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
            return self._verdict_builder.approve(
                rule=rule,
                tool_name=tool_name,
                args=args,
            )
        else:
            return self._verdict_builder.allow(rule=rule, args=args)

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

    def post_check(
        self,
        tool_name: str,
        result: Any,
        session_id: str = "default",
    ) -> ShieldResult:
        """Post-call check on tool output (for PII in results).

        Args:
            tool_name: Name of the tool.
            result: The tool's return value.
            session_id: Session identifier.

        Returns:
            ShieldResult (currently always ALLOW).
        """
        if self._mode == ShieldMode.DISABLED:
            return self._verdict_builder.allow()

        # Scan output for PII
        if isinstance(result, dict):
            pii_matches = self._pii.scan_dict(result)
            for pm in pii_matches:
                self._session_mgr.add_taint(session_id, pm.pii_type)

        return self._verdict_builder.allow()

    def reload_rules(self, path: str | Path) -> None:
        """Reload rules from a new path.

        Args:
            path: Path to YAML file or directory.
        """
        self._rule_set = load_rules(path)
        self._matcher = MatcherEngine(self._rule_set)
        logger.info("Rules reloaded from %s (%d rules)", path, len(self._rule_set.rules))

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
        return self._matcher.rule_count
