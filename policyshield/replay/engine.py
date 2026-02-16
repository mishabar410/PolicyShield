"""Replay engine — re-evaluates historical traces against new rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from policyshield.core.models import RuleSet
from policyshield.core.parser import load_rules
from policyshield.replay.loader import TraceEntry
from policyshield.shield.matcher import MatcherEngine


class ChangeType(Enum):
    """Type of verdict change in replay."""

    UNCHANGED = "unchanged"
    RELAXED = "relaxed"  # e.g. BLOCK → ALLOW (less restrictive)
    TIGHTENED = "tightened"  # e.g. ALLOW → BLOCK (more restrictive)
    MODIFIED = "modified"  # e.g. BLOCK → REDACT (different, same level)


@dataclass(frozen=True)
class ReplayResult:
    """Result of replaying a single trace entry against new rules."""

    entry: TraceEntry
    old_verdict: str
    new_verdict: str
    new_rule_id: str | None
    change_type: ChangeType

    @property
    def changed(self) -> bool:
        return self.change_type != ChangeType.UNCHANGED


_VERDICT_RANK = {"allow": 0, "redact": 1, "approve": 2, "block": 3}


def _classify_change(old: str, new: str) -> ChangeType:
    """Classify the verdict change."""
    old_r = _VERDICT_RANK.get(old.lower(), -1)
    new_r = _VERDICT_RANK.get(new.lower(), -1)
    if old_r == new_r:
        return ChangeType.UNCHANGED
    if new_r < old_r:
        return ChangeType.RELAXED
    if new_r > old_r:
        return ChangeType.TIGHTENED
    return ChangeType.MODIFIED


class ReplayEngine:
    """Replays trace entries against a rule set.

    Args:
        rule_set: The new RuleSet to evaluate against.
    """

    def __init__(self, rule_set: RuleSet) -> None:
        self._matcher = MatcherEngine(rule_set)
        self._default_verdict = rule_set.default_verdict.value

    @classmethod
    def from_file(cls, rules_path: str) -> ReplayEngine:
        """Create a ReplayEngine from a rules YAML file."""
        rule_set = load_rules(rules_path)
        return cls(rule_set)

    def replay_one(self, entry: TraceEntry) -> ReplayResult:
        """Replay a single trace entry.

        Args:
            entry: The trace entry to replay.

        Returns:
            ReplayResult with old and new verdicts.
        """
        match = self._matcher.find_best_match(
            tool_name=entry.tool,
            args=entry.args or {},
        )

        if match:
            new_verdict = match.rule.then.value
            new_rule_id = match.rule.id
        else:
            new_verdict = self._default_verdict
            new_rule_id = None

        change_type = _classify_change(entry.verdict, new_verdict)

        return ReplayResult(
            entry=entry,
            old_verdict=entry.verdict,
            new_verdict=new_verdict,
            new_rule_id=new_rule_id,
            change_type=change_type,
        )

    def replay_all(self, entries: list[TraceEntry]) -> list[ReplayResult]:
        """Replay all trace entries.

        Returns:
            List of ReplayResult, one per entry.
        """
        return [self.replay_one(e) for e in entries]

    def summary(self, results: list[ReplayResult]) -> dict:
        """Generate a summary of replay results.

        Returns:
            Dict with total, changed, unchanged, relaxed, tightened counts.
        """
        changed = [r for r in results if r.changed]
        return {
            "total": len(results),
            "unchanged": len(results) - len(changed),
            "changed": len(changed),
            "relaxed": sum(1 for r in changed if r.change_type == ChangeType.RELAXED),
            "tightened": sum(1 for r in changed if r.change_type == ChangeType.TIGHTENED),
            "modified": sum(1 for r in changed if r.change_type == ChangeType.MODIFIED),
        }
