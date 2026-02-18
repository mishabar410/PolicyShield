"""Dead rule detection — find rules that never matched in traces."""

from __future__ import annotations

import json
from pathlib import Path

from policyshield.core.models import RuleSet


def find_dead_rules(
    ruleset: RuleSet,
    trace_dir: str | Path,
) -> list[str]:
    """Find rule IDs that never appeared in any trace file.

    Args:
        ruleset: The active ruleset to check.
        trace_dir: Directory containing trace JSONL files.

    Returns:
        List of rule IDs that never matched.
    """
    all_rule_ids = {r.id for r in ruleset.rules}
    matched_ids: set[str] = set()

    trace_path = Path(trace_dir)
    for trace_file in trace_path.glob("trace_*.jsonl"):
        with open(trace_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    rid = entry.get("rule_id")
                    if rid and rid in all_rule_ids:
                        matched_ids.add(rid)
                except json.JSONDecodeError:
                    continue

    return sorted(all_rule_ids - matched_ids)
