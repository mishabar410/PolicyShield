"""Rule linter — static analysis for PolicyShield YAML rules."""

from __future__ import annotations

import re
from dataclasses import dataclass

from policyshield.core.models import RuleSet


@dataclass
class LintWarning:
    """A single lint finding."""

    level: str  # ERROR, WARNING, INFO
    rule_id: str  # ID of the rule (or "*" for global issues)
    check: str  # Name of the check (duplicate_ids, invalid_regex, ...)
    message: str  # Human-readable description


class RuleLinter:
    """Static analyzer for PolicyShield rule sets.

    Runs a set of checks on a RuleSet and returns a list of LintWarning.
    """

    def lint(self, ruleset: RuleSet) -> list[LintWarning]:
        """Run all lint checks on a rule set.

        Args:
            ruleset: The RuleSet to analyze.

        Returns:
            List of LintWarning findings.
        """
        warnings: list[LintWarning] = []
        warnings.extend(self.check_duplicate_ids(ruleset))
        warnings.extend(self.check_invalid_regex(ruleset))
        warnings.extend(self.check_broad_tool_pattern(ruleset))
        warnings.extend(self.check_missing_message(ruleset))
        warnings.extend(self.check_conflicting_verdicts(ruleset))
        warnings.extend(self.check_disabled_rules(ruleset))
        return warnings

    def check_duplicate_ids(self, ruleset: RuleSet) -> list[LintWarning]:
        """Check for duplicate rule IDs."""
        warnings: list[LintWarning] = []
        seen: dict[str, int] = {}
        for idx, rule in enumerate(ruleset.rules):
            if rule.id in seen:
                warnings.append(
                    LintWarning(
                        level="ERROR",
                        rule_id=rule.id,
                        check="duplicate_ids",
                        message=f"Duplicate rule ID '{rule.id}' (first seen in rule #{seen[rule.id] + 1})",
                    )
                )
            else:
                seen[rule.id] = idx
        return warnings

    def check_invalid_regex(self, ruleset: RuleSet) -> list[LintWarning]:
        """Check for invalid regex patterns in args_match."""
        warnings: list[LintWarning] = []
        for rule in ruleset.rules:
            args_match = rule.when.get("args_match", {})
            if not isinstance(args_match, dict):
                continue
            for field, matcher in args_match.items():
                # Extract the regex pattern
                pattern = None
                if isinstance(matcher, dict):
                    pattern = matcher.get("regex")
                elif isinstance(matcher, str):
                    pattern = matcher
                if pattern is not None:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        warnings.append(
                            LintWarning(
                                level="ERROR",
                                rule_id=rule.id,
                                check="invalid_regex",
                                message=f"Invalid regex in args_match.{field}: '{pattern}' ({e})",
                            )
                        )
        return warnings

    def check_broad_tool_pattern(self, ruleset: RuleSet) -> list[LintWarning]:
        """Check for overly broad tool patterns like '.*' or '.+'."""
        warnings: list[LintWarning] = []
        broad_patterns = {".*", ".+"}
        for rule in ruleset.rules:
            tool = rule.when.get("tool", "")
            tools = tool if isinstance(tool, list) else [tool]
            for t in tools:
                if isinstance(t, str) and t in broad_patterns:
                    warnings.append(
                        LintWarning(
                            level="WARNING",
                            rule_id=rule.id,
                            check="broad_tool_pattern",
                            message=f"Tool pattern '{t}' matches all tools",
                        )
                    )
        return warnings

    def check_missing_message(self, ruleset: RuleSet) -> list[LintWarning]:
        """Check for BLOCK rules without a message."""
        warnings: list[LintWarning] = []
        from policyshield.core.models import Verdict

        for rule in ruleset.rules:
            if rule.then == Verdict.BLOCK and not rule.message:
                warnings.append(
                    LintWarning(
                        level="WARNING",
                        rule_id=rule.id,
                        check="missing_message",
                        message="Rule with 'then: block' has no message — agent won't get an explanation",
                    )
                )
        return warnings

    def check_conflicting_verdicts(self, ruleset: RuleSet) -> list[LintWarning]:
        """Check for rules with the same tool and overlapping args_match but different verdicts."""
        warnings: list[LintWarning] = []
        # Group rules by tool pattern
        tool_groups: dict[str, list] = {}
        for rule in ruleset.rules:
            if not rule.enabled:
                continue
            tool = rule.when.get("tool", "")
            # Normalize tool to a hashable key
            if isinstance(tool, list):
                tool_key = tuple(sorted(tool))
            else:
                tool_key = tool
            if tool_key:
                tool_groups.setdefault(tool_key, []).append(rule)

        for tool, rules in tool_groups.items():
            if len(rules) < 2:
                continue
            for i, r1 in enumerate(rules):
                for r2 in rules[i + 1 :]:
                    if r1.then != r2.then:
                        # Check if args_match patterns overlap
                        am1 = r1.when.get("args_match", {})
                        am2 = r2.when.get("args_match", {})
                        if self._args_overlap(am1, am2):
                            warnings.append(
                                LintWarning(
                                    level="WARNING",
                                    rule_id=r1.id,
                                    check="conflicting_verdicts",
                                    message=(
                                        f"Rules '{r1.id}' ({r1.then.value}) and '{r2.id}' "
                                        f"({r2.then.value}) match tool '{tool}' with overlapping args"
                                    ),
                                )
                            )
        return warnings

    @staticmethod
    def _args_overlap(am1: dict, am2: dict) -> bool:
        """Heuristic: check if two args_match patterns could overlap.

        If both are empty, they overlap (both match everything).
        If they share the same field with the same or similar regex, they overlap.
        This is a conservative heuristic — it may report false positives.
        """
        if not am1 or not am2:
            return True  # One or both match everything
        # Check for shared fields with similar patterns
        fields1 = set(am1.keys()) if isinstance(am1, dict) else set()
        fields2 = set(am2.keys()) if isinstance(am2, dict) else set()
        shared = fields1 & fields2
        if not shared:
            return True  # Different fields — could still overlap
        return True  # Conservative: assume overlap

    def check_disabled_rules(self, ruleset: RuleSet) -> list[LintWarning]:
        """Report disabled rules as INFO."""
        warnings: list[LintWarning] = []
        for rule in ruleset.rules:
            if not rule.enabled:
                warnings.append(
                    LintWarning(
                        level="INFO",
                        rule_id=rule.id,
                        check="disabled_rules",
                        message="Rule is disabled",
                    )
                )
        return warnings
