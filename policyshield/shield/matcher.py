"""Matcher engine for PolicyShield — matches tool calls against rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from policyshield.core.models import ChainCondition, RuleConfig, RuleSet, Severity, Verdict

# Maximum length for regex patterns to prevent ReDoS
MAX_PATTERN_LENGTH = 500


@dataclass
class CompiledRule:
    """A rule with pre-compiled regex patterns for efficient matching."""

    rule: RuleConfig
    tool_pattern: re.Pattern | None = None
    arg_patterns: list[tuple[str, str, re.Pattern]] = field(default_factory=list)
    sender_pattern: re.Pattern | None = None

    @classmethod
    def from_rule(cls, rule: RuleConfig) -> CompiledRule:
        """Create a CompiledRule from a RuleConfig.

        Tool matching behaviour:
        - **list**: each entry is treated as an exact tool name
          (``re.escape``-d, joined with ``|``).  ``["a", "b"]`` matches
          only ``"a"`` and ``"b"``.
        - **string**: treated as a regex pattern anchored with ``^...$``.
          ``"file_.*"`` matches any tool starting with ``file_``.
        """
        when = rule.when
        compiled = cls(rule=rule)

        # Compile tool pattern
        tool = when.get("tool")
        if tool:
            if isinstance(tool, list):
                # List of tool names → alternation regex (exact match)
                escaped = [re.escape(t) for t in tool]
                compiled.tool_pattern = re.compile(f"^({'|'.join(escaped)})$")
            else:
                if len(str(tool)) > MAX_PATTERN_LENGTH:
                    raise ValueError(f"Tool pattern in rule '{rule.id}' exceeds {MAX_PATTERN_LENGTH} characters")
                compiled.tool_pattern = re.compile(f"^{tool}$")

        # Compile argument matchers (support both 'args' and 'args_match')
        args = when.get("args") or when.get("args_match") or {}
        if isinstance(args, dict):
            for field_name, condition in args.items():
                if isinstance(condition, dict):
                    # Support shorthand: {regex: "..."} or {eq: "..."}
                    if "predicate" in condition:
                        predicate = condition["predicate"]
                        value = condition.get("value", "")
                    elif "regex" in condition:
                        predicate = "regex"
                        value = condition["regex"]
                    elif "eq" in condition:
                        predicate = "eq"
                        value = condition["eq"]
                    elif "contains" in condition:
                        predicate = "contains"
                        value = condition["contains"]
                    else:
                        predicate = "regex"
                        value = str(next(iter(condition.values()), ""))
                else:
                    predicate = "regex"
                    value = str(condition)
                if len(value) > MAX_PATTERN_LENGTH:
                    raise ValueError(
                        f"Regex pattern for field '{field_name}' in rule "
                        f"'{rule.id}' exceeds {MAX_PATTERN_LENGTH} characters"
                    )
                compiled.arg_patterns.append((field_name, predicate, re.compile(value)))

        # Compile sender pattern
        sender = when.get("sender")
        if sender:
            if len(str(sender)) > MAX_PATTERN_LENGTH:
                raise ValueError(f"Sender pattern in rule '{rule.id}' exceeds {MAX_PATTERN_LENGTH} characters")
            compiled.sender_pattern = re.compile(f"^{sender}$")

        return compiled


# Priority score for verdicts (higher = more restrictive)
_VERDICT_PRIORITY: dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.REDACT: 1,
    Verdict.APPROVE: 2,
    Verdict.BLOCK: 3,
}

_SEVERITY_PRIORITY: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class MatcherEngine:
    """Matches tool calls against a rule set.

    Rules are indexed by tool name for fast lookup. Wildcard rules
    apply to all tools.
    """

    def __init__(self, rule_set: RuleSet):
        self._rule_set = rule_set
        self._compiled: list[CompiledRule] = []
        self._tool_index: dict[str, list[CompiledRule]] = {}
        self._wildcard_rules: list[CompiledRule] = []
        self._build_index()

    def _build_index(self) -> None:
        """Build the lookup index from enabled rules."""
        self._compiled = []
        self._tool_index = {}
        self._wildcard_rules = []

        for rule in self._rule_set.enabled_rules():
            compiled = CompiledRule.from_rule(rule)
            self._compiled.append(compiled)

            tool = rule.when.get("tool")
            if isinstance(tool, list):
                # List of tool names — index each one
                for t in tool:
                    self._tool_index.setdefault(t, []).append(compiled)
            elif tool and not any(c in tool for c in ("*", ".", "+", "?", "[", "|")):
                # Exact tool name — index it
                self._tool_index.setdefault(tool, []).append(compiled)
            else:
                # Wildcard or regex tool pattern
                self._wildcard_rules.append(compiled)

    def find_matching_rules(
        self,
        tool_name: str,
        args: dict | None = None,
        session_state: dict | None = None,
        sender: str | None = None,
        event_buffer: object | None = None,
    ) -> list[CompiledRule]:
        """Find all rules matching a tool call.

        Args:
            tool_name: Name of the tool being called.
            args: Arguments to the tool call.
            session_state: Current session state for session-based conditions.
            sender: Identity of the caller.
            event_buffer: Optional EventRingBuffer for chain rule evaluation.

        Returns:
            List of matching CompiledRule objects, sorted by priority.
        """
        args = args or {}
        candidates = list(self._tool_index.get(tool_name, []))
        candidates.extend(self._wildcard_rules)

        matching: list[CompiledRule] = []
        for compiled in candidates:
            if self._matches(compiled, tool_name, args, session_state, sender, event_buffer):
                matching.append(compiled)

        # Sort: most restrictive verdict first, then by severity
        matching.sort(
            key=lambda c: (
                _VERDICT_PRIORITY.get(c.rule.then, 0),
                _SEVERITY_PRIORITY.get(c.rule.severity, 0),
            ),
            reverse=True,
        )
        return matching

    def find_best_match(
        self,
        tool_name: str,
        args: dict | None = None,
        session_state: dict | None = None,
        sender: str | None = None,
        event_buffer: object | None = None,
    ) -> CompiledRule | None:
        """Find the highest-priority matching rule.

        Returns:
            The most restrictive matching rule, or None.
        """
        matches = self.find_matching_rules(tool_name, args, session_state, sender, event_buffer)
        return matches[0] if matches else None

    def _matches(
        self,
        compiled: CompiledRule,
        tool_name: str,
        args: dict,
        session_state: dict | None,
        sender: str | None,
        event_buffer: object | None = None,
    ) -> bool:
        """Check if a compiled rule matches a tool call."""
        # Check tool name
        if compiled.tool_pattern and not compiled.tool_pattern.match(tool_name):
            return False

        # Check arguments
        for field_name, predicate, pattern in compiled.arg_patterns:
            arg_value = args.get(field_name)
            if arg_value is None:
                return False
            arg_str = str(arg_value)
            if predicate == "regex":
                if not pattern.search(arg_str):
                    return False
            elif predicate == "eq":
                if arg_str != pattern.pattern:
                    return False
            elif predicate == "contains":
                if pattern.pattern not in arg_str:
                    return False
            elif predicate == "not_contains":
                if pattern.pattern in arg_str:
                    return False
            else:
                # Unknown predicate — treat as regex
                if not pattern.search(arg_str):
                    return False

        # Check session state conditions
        when = compiled.rule.when
        session_conditions = when.get("session", {})
        if session_conditions and session_state:
            for key, condition in session_conditions.items():
                actual = session_state.get(key)
                if isinstance(condition, dict):
                    # Comparison operators
                    if "gt" in condition and not (actual is not None and actual > condition["gt"]):
                        return False
                    if "gte" in condition and not (actual is not None and actual >= condition["gte"]):
                        return False
                    if "lt" in condition and not (actual is not None and actual < condition["lt"]):
                        return False
                    if "lte" in condition and not (actual is not None and actual <= condition["lte"]):
                        return False
                    if "eq" in condition and actual != condition["eq"]:
                        return False
                else:
                    if actual != condition:
                        return False
        elif session_conditions and not session_state:
            return False

        # Check sender
        if compiled.sender_pattern:
            if not sender or not compiled.sender_pattern.match(sender):
                return False

        # Check chain conditions
        if compiled.rule.chain and not self._check_chain(compiled.rule.chain, event_buffer):
            return False

        return True

    def _check_chain(
        self,
        chain: list[dict],
        event_buffer: Any,
    ) -> bool:
        """Check whether all chain prerequisites are satified in the event buffer."""
        if event_buffer is None:
            return False
        for step in chain:
            cond = ChainCondition(**step)
            matches = event_buffer.find_recent(  # type: ignore[union-attr]
                cond.tool,
                within_seconds=cond.within_seconds,
                verdict=cond.verdict,
            )
            if len(matches) < cond.min_count:
                return False
        return True

    @property
    def rule_count(self) -> int:
        """Return total number of compiled rules."""
        return len(self._compiled)
