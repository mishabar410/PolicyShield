# Prompt 102 — Replay Engine

## Цель

Создать `policyshield/replay/engine.py` — движок replay, который прогоняет загруженные трейсы через матчер с новыми правилами и генерирует diff: old verdict vs new verdict.

## Контекст

- `TraceLoader` из промпта 101 загружает `TraceEntry` из JSONL
- `MatcherEngine` (`shield/matcher.py`) сопоставляет tool calls с правилами
- Replay: для каждого `TraceEntry` → вызвать матчер → сравнить `entry.verdict` с новым
- Результат: список `ReplayResult` с old/new verdict и флагом `changed`

## Что сделать

### 1. Создать `policyshield/replay/engine.py`

```python
"""Replay engine — re-evaluates historical traces against new rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from policyshield.core.models import RuleSet, Verdict
from policyshield.core.parser import parse_rules
from policyshield.replay.loader import TraceEntry
from policyshield.shield.matcher import MatcherEngine


class ChangeType(Enum):
    """Type of verdict change in replay."""
    UNCHANGED = "unchanged"
    RELAXED = "relaxed"      # e.g. BLOCK → ALLOW (less restrictive)
    TIGHTENED = "tightened"  # e.g. ALLOW → BLOCK (more restrictive)
    MODIFIED = "modified"    # e.g. BLOCK → REDACT (different, same level)


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
        rule_set = parse_rules(rules_path)
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
            new_verdict = match.verdict.value
            new_rule_id = match.id
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
```

### 2. Обновить `policyshield/replay/__init__.py`

```python
from policyshield.replay.loader import TraceEntry, TraceLoader
from policyshield.replay.engine import ReplayEngine, ReplayResult, ChangeType

__all__ = ["TraceEntry", "TraceLoader", "ReplayEngine", "ReplayResult", "ChangeType"]
```

### 3. Тесты

#### `tests/test_replay_engine.py`

```python
from policyshield.replay.loader import TraceEntry
from policyshield.replay.engine import ReplayEngine, ChangeType, _classify_change
from policyshield.core.models import RuleSet, RuleConfig, Verdict


def _make_ruleset(rules, default=Verdict.ALLOW):
    return RuleSet(shield_name="test", version="1", rules=rules, default_verdict=default)


def test_replay_unchanged():
    rules = _make_ruleset([
        RuleConfig(id="r1", when={"tool": "read_file"}, verdict=Verdict.ALLOW),
    ])
    engine = ReplayEngine(rules)
    entry = TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="read_file", verdict="allow")
    result = engine.replay_one(entry)
    assert not result.changed
    assert result.change_type == ChangeType.UNCHANGED


def test_replay_tightened():
    rules = _make_ruleset([
        RuleConfig(id="r1", when={"tool": "read_file"}, verdict=Verdict.BLOCK),
    ])
    engine = ReplayEngine(rules)
    entry = TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="read_file", verdict="allow")
    result = engine.replay_one(entry)
    assert result.changed
    assert result.change_type == ChangeType.TIGHTENED
    assert result.new_verdict == "block"


def test_replay_relaxed():
    rules = _make_ruleset([
        RuleConfig(id="r1", when={"tool": "delete_file"}, verdict=Verdict.ALLOW),
    ])
    engine = ReplayEngine(rules)
    entry = TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="delete_file", verdict="block")
    result = engine.replay_one(entry)
    assert result.changed
    assert result.change_type == ChangeType.RELAXED


def test_replay_all_with_summary():
    rules = _make_ruleset([
        RuleConfig(id="r1", when={"tool": "read_file"}, verdict=Verdict.ALLOW),
        RuleConfig(id="r2", when={"tool": "delete_file"}, verdict=Verdict.BLOCK),
    ])
    engine = ReplayEngine(rules)
    entries = [
        TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="read_file", verdict="allow"),
        TraceEntry(timestamp="2026-01-01T00:01:00+00:00", session_id="s1", tool="delete_file", verdict="allow"),
    ]
    results = engine.replay_all(entries)
    summary = engine.summary(results)
    assert summary["total"] == 2
    assert summary["unchanged"] == 1
    assert summary["tightened"] == 1


def test_default_verdict_used_when_no_match():
    rules = _make_ruleset([], default=Verdict.BLOCK)
    engine = ReplayEngine(rules)
    entry = TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="unknown", verdict="allow")
    result = engine.replay_one(entry)
    assert result.new_verdict == "block"
    assert result.change_type == ChangeType.TIGHTENED


def test_classify_change():
    assert _classify_change("allow", "allow") == ChangeType.UNCHANGED
    assert _classify_change("allow", "block") == ChangeType.TIGHTENED
    assert _classify_change("block", "allow") == ChangeType.RELAXED
```

## Самопроверка

```bash
pytest tests/test_replay_engine.py -v
pytest tests/ -q
```

## Коммит

```
feat(replay): add replay engine — compare old vs new verdicts

- Add ReplayEngine: replays TraceEntry against new RuleSet
- Add ChangeType enum: UNCHANGED, RELAXED, TIGHTENED, MODIFIED
- Add ReplayResult with old/new verdict and change classification
- Summary helper: total, changed, relaxed, tightened counts
```
