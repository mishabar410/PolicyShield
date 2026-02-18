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

    # Check for shadowing (same tool pattern, different verdict)
    for i, (file_a, rules_a) in enumerate(file_rules):
        for j, (file_b, rules_b) in enumerate(file_rules):
            if i >= j:
                continue
            for ra in rules_a:
                for rb in rules_b:
                    if ra.id == rb.id:
                        continue
                    tool_a = ra.when.get("tool", ".*")
                    tool_b = rb.when.get("tool", ".*")
                    if _patterns_overlap(tool_a, tool_b) and ra.then != rb.then:
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
