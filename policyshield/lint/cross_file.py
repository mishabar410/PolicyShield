"""Cross-file rule validation — detects conflicts and shadowing."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from policyshield.core.models import RuleConfig
from policyshield.core.parser import load_rules


@dataclass
class CrossFileIssue:
    severity: str  # "error" | "warning"
    message: str
    file_a: str
    rule_a: str
    file_b: str | None = None
    rule_b: str | None = None


def find_cross_file_issues(rule_files: list[Path]) -> list[CrossFileIssue]:
    """Find conflicts and shadowing between multiple rule files."""
    issues: list[CrossFileIssue] = []

    # Load all rulesets
    file_rules: list[tuple[Path, list[RuleConfig]]] = []
    for f in rule_files:
        try:
            rs = load_rules(f)
            file_rules.append((f, rs.rules))
        except Exception as e:
            issues.append(
                CrossFileIssue(
                    severity="error",
                    message=f"Cannot parse: {e}",
                    file_a=str(f),
                    rule_a="*",
                )
            )

    # Check for duplicate IDs
    seen_ids: dict[str, Path] = {}
    for file_path, rules in file_rules:
        for rule in rules:
            if rule.id in seen_ids:
                issues.append(
                    CrossFileIssue(
                        severity="error",
                        message=f"Duplicate rule ID: {rule.id}",
                        file_a=str(seen_ids[rule.id]),
                        rule_a=rule.id,
                        file_b=str(file_path),
                        rule_b=rule.id,
                    )
                )
            seen_ids[rule.id] = file_path

    # Check for shadowing — build tool_pattern → [(file, rule)] map in one pass
    from collections import defaultdict as _dd

    pattern_map: dict[str, list[tuple[Path, RuleConfig]]] = _dd(list)
    for file_path, rules in file_rules:
        for rule in rules:
            pattern = str(rule.when.get("tool", ".*"))
            pattern_map[pattern].append((file_path, rule))

    seen_conflicts: set[frozenset] = set()
    for pattern, entries in pattern_map.items():
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                file_a, ra = entries[i]
                file_b, rb = entries[j]
                if ra.id == rb.id:
                    continue
                conflict_key = frozenset([ra.id, rb.id])
                if conflict_key in seen_conflicts:
                    continue
                if ra.then != rb.then:
                    seen_conflicts.add(conflict_key)
                    issues.append(
                        CrossFileIssue(
                            severity="warning",
                            message=(
                                f"Conflicting verdicts for overlapping tool patterns: "
                                f"{ra.then.value} vs {rb.then.value}"
                            ),
                            file_a=str(file_a),
                            rule_a=ra.id,
                            file_b=str(file_b),
                            rule_b=rb.id,
                        )
                    )

    return issues


def _patterns_overlap(pattern_a: object, pattern_b: object) -> bool:
    """Heuristic check if two tool patterns might overlap."""
    if str(pattern_a) == str(pattern_b):
        return True
    if pattern_a == ".*" or pattern_b == ".*":
        return True
    if isinstance(pattern_a, list) and isinstance(pattern_b, list):
        return bool(set(pattern_a) & set(pattern_b))
    return False
