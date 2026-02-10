"""Verdict builder for PolicyShield — constructs ShieldResult with counterexamples."""

from __future__ import annotations

from policyshield.core.models import PIIMatch, RuleConfig, ShieldResult, Verdict


# Default suggestions per verdict type
_DEFAULT_SUGGESTIONS: dict[Verdict, str] = {
    Verdict.BLOCK: "Consider using a safer alternative or requesting elevated permissions.",
    Verdict.APPROVE: "This action requires human approval before proceeding.",
    Verdict.REDACT: "PII was detected and will be redacted from the arguments.",
}


class VerdictBuilder:
    """Builds ShieldResult objects with structured counterexamples.

    Counterexamples help AI agents understand what went wrong and
    how to fix it (repair loop).
    """

    def allow(
        self,
        rule: RuleConfig | None = None,
        args: dict | None = None,
    ) -> ShieldResult:
        """Build an ALLOW result."""
        return ShieldResult(
            verdict=Verdict.ALLOW,
            rule_id=rule.id if rule else None,
            message="Tool call allowed.",
            original_args=args,
        )

    def block(
        self,
        rule: RuleConfig,
        tool_name: str,
        args: dict | None = None,
        pii_matches: list[PIIMatch] | None = None,
    ) -> ShieldResult:
        """Build a BLOCK result with counterexample."""
        message = self._format_counterexample(
            verdict=Verdict.BLOCK,
            rule=rule,
            tool_name=tool_name,
            args=args,
            pii_matches=pii_matches,
        )
        return ShieldResult(
            verdict=Verdict.BLOCK,
            rule_id=rule.id,
            message=message,
            pii_matches=pii_matches or [],
            original_args=args,
        )

    def redact(
        self,
        rule: RuleConfig,
        tool_name: str,
        args: dict | None = None,
        modified_args: dict | None = None,
        pii_matches: list[PIIMatch] | None = None,
    ) -> ShieldResult:
        """Build a REDACT result with modified arguments."""
        message = self._format_counterexample(
            verdict=Verdict.REDACT,
            rule=rule,
            tool_name=tool_name,
            args=args,
            pii_matches=pii_matches,
        )
        return ShieldResult(
            verdict=Verdict.REDACT,
            rule_id=rule.id,
            message=message,
            pii_matches=pii_matches or [],
            original_args=args,
            modified_args=modified_args,
        )

    def approve(
        self,
        rule: RuleConfig,
        tool_name: str,
        args: dict | None = None,
    ) -> ShieldResult:
        """Build an APPROVE result (requires human approval)."""
        message = self._format_counterexample(
            verdict=Verdict.APPROVE,
            rule=rule,
            tool_name=tool_name,
            args=args,
        )
        return ShieldResult(
            verdict=Verdict.APPROVE,
            rule_id=rule.id,
            message=message,
            original_args=args,
        )

    def _format_counterexample(
        self,
        verdict: Verdict,
        rule: RuleConfig,
        tool_name: str,
        args: dict | None = None,
        pii_matches: list[PIIMatch] | None = None,
    ) -> str:
        """Format a human-readable counterexample message.

        Format:
            [VERDICT] tool_name — rule description
            Rule: rule_id
            Reason: rule message or default
            Suggestion: helpful guidance
            PII: detected types (if any)
        """
        parts: list[str] = []

        # Header
        desc = rule.description or rule.id
        parts.append(f"[{verdict.value}] {tool_name} — {desc}")

        # Rule info
        parts.append(f"Rule: {rule.id}")

        # Reason
        reason = rule.message or f"Matched rule '{rule.id}'"
        parts.append(f"Reason: {reason}")

        # Suggestion
        suggestion = _DEFAULT_SUGGESTIONS.get(verdict, "")
        if suggestion:
            parts.append(f"Suggestion: {suggestion}")

        # PII info
        if pii_matches:
            pii_types = sorted({m.pii_type.value for m in pii_matches})
            parts.append(f"PII detected: {', '.join(pii_types)}")

        return "\n".join(parts)
