"""Compare two PolicyShield rule sets and produce a structured diff.

Useful for code review, CI/CD gates, and policy change tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from policyshield.core.models import RuleConfig, RuleSet

# Fields to compare (skip 'id' since it's the match key)
_COMPARE_FIELDS = ("description", "when", "then", "message", "severity", "enabled", "approval_strategy")


@dataclass
class FieldChange:
    """A single field-level change between old and new rule."""

    field: str
    old_value: Any
    new_value: Any


@dataclass
class RuleModification:
    """A rule that exists in both sets but with different field values."""

    rule_id: str
    changes: list[FieldChange] = field(default_factory=list)


@dataclass
class RuleDiff:
    """Result of comparing two rule sets."""

    added: list[RuleConfig] = field(default_factory=list)
    removed: list[RuleConfig] = field(default_factory=list)
    modified: list[RuleModification] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)


class PolicyDiffer:
    """Compare two :class:`RuleSet` instances and produce a :class:`RuleDiff`."""

    @staticmethod
    def diff(old: RuleSet, new: RuleSet) -> RuleDiff:
        """Compute the diff between *old* and *new* rule sets.

        Rules are matched by their ``id`` field.
        """
        old_map = {r.id: r for r in old.rules}
        new_map = {r.id: r for r in new.rules}

        old_ids = set(old_map)
        new_ids = set(new_map)

        result = RuleDiff()

        # Added
        for rid in sorted(new_ids - old_ids):
            result.added.append(new_map[rid])

        # Removed
        for rid in sorted(old_ids - new_ids):
            result.removed.append(old_map[rid])

        # Modified / unchanged
        for rid in sorted(old_ids & new_ids):
            old_rule = old_map[rid]
            new_rule = new_map[rid]
            changes: list[FieldChange] = []

            for fld in _COMPARE_FIELDS:
                old_val = getattr(old_rule, fld)
                new_val = getattr(new_rule, fld)

                # Normalize enums to their values for comparison
                old_cmp = old_val.value if hasattr(old_val, "value") else old_val
                new_cmp = new_val.value if hasattr(new_val, "value") else new_val

                if old_cmp != new_cmp:
                    changes.append(FieldChange(field=fld, old_value=old_cmp, new_value=new_cmp))

            if changes:
                result.modified.append(RuleModification(rule_id=rid, changes=changes))
            else:
                result.unchanged += 1

        return result

    @staticmethod
    def format_diff(diff: RuleDiff) -> str:
        """Format *diff* for terminal display with +/-/~ markers."""
        lines: list[str] = []

        for rule in diff.added:
            lines.append(f"+ ADDED: {rule.id}")
            lines.append(f"  → {rule.then.value} [{rule.severity.value}] {rule.description!r}")
            lines.append("")

        for rule in diff.removed:
            lines.append(f"- REMOVED: {rule.id}")
            lines.append(f"  → {rule.then.value} [{rule.severity.value}] {rule.description!r}")
            lines.append("")

        for mod in diff.modified:
            lines.append(f"~ MODIFIED: {mod.rule_id}")
            for ch in mod.changes:
                lines.append(f"  {ch.field}: {ch.old_value!r} → {ch.new_value!r}")
            lines.append("")

        parts = []
        if diff.added:
            parts.append(f"{len(diff.added)} added")
        if diff.removed:
            parts.append(f"{len(diff.removed)} removed")
        if diff.modified:
            parts.append(f"{len(diff.modified)} modified")
        parts.append(f"{diff.unchanged} unchanged")
        lines.append(f"Summary: {', '.join(parts)}")

        return "\n".join(lines)

    @staticmethod
    def diff_to_dict(diff: RuleDiff) -> dict:
        """Convert *diff* to a JSON-serializable dict."""
        return {
            "added": [{"id": r.id, "then": r.then.value, "severity": r.severity.value} for r in diff.added],
            "removed": [{"id": r.id, "then": r.then.value, "severity": r.severity.value} for r in diff.removed],
            "modified": [
                {
                    "rule_id": m.rule_id,
                    "changes": [{"field": c.field, "old": c.old_value, "new": c.new_value} for c in m.changes],
                }
                for m in diff.modified
            ],
            "unchanged": diff.unchanged,
        }
