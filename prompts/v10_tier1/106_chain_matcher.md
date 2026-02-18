# Prompt 106 — Chain Matcher

## Цель

Реализовать matching chain conditions: при найденном tool match проверить, что все `chain` условия выполнены (соответствующие вызовы были в event buffer в заданном временном окне).

## Контекст

- `EventRingBuffer` (промпт 104) хранит историю вызовов в сессии
- `ChainCondition` (промпт 105) описывает «tool X за последние N сек»
- `MatcherEngine._matches()` (`shield/matcher.py`) сейчас проверяет tool + args + sender
- Нужно добавить проверку chain conditions, если они есть в правиле
- Нужен доступ к `SessionState.event_buffer` из matcher

## Что сделать

### 1. Добавить `_check_chain()` в `MatcherEngine` (`shield/matcher.py`)

```python
from policyshield.shield.ring_buffer import EventRingBuffer

def _check_chain(
    self,
    chain: list[ChainCondition],
    event_buffer: EventRingBuffer | None,
) -> bool:
    """Check if all chain conditions are satisfied.

    Args:
        chain: List of chain conditions from the rule.
        event_buffer: The session's event ring buffer.

    Returns:
        True if all conditions are met (or chain is empty).
    """
    if not chain:
        return True

    if event_buffer is None:
        return False  # Can't match chain without history

    for condition in chain:
        events = event_buffer.find_recent(
            condition.tool,
            within_seconds=condition.within_seconds,
            verdict=condition.verdict,
        )
        if not events:
            return False  # This condition is not satisfied

    return True
```

### 2. Интегрировать в `_matches()`

В `MatcherEngine._matches()`, после проверки tool + args + sender:

```python
def _matches(
    self,
    compiled: CompiledRule,
    tool_name: str,
    args: dict,
    session_state: dict | None,
    sender: str | None,
    event_buffer: EventRingBuffer | None = None,  # NEW
) -> bool:
    # ... existing tool pattern check ...
    # ... existing args check ...
    # ... existing sender check ...

    # Chain conditions
    if compiled.rule.chain:
        if not self._check_chain(compiled.rule.chain, event_buffer):
            return False

    return True
```

### 3. Прокинуть `event_buffer` через API

В `find_matching_rules()` и `find_best_match()`:

```python
def find_matching_rules(
    self,
    tool_name: str,
    args: dict | None = None,
    session_state: dict | None = None,
    sender: str | None = None,
    event_buffer: EventRingBuffer | None = None,  # NEW
) -> list[RuleConfig]:
    ...
    for compiled in candidates:
        if self._matches(compiled, tool_name, args or {}, session_state, sender, event_buffer):
            matches.append(compiled.rule)
    ...
```

### 4. Тесты

#### `tests/test_chain_matcher.py`

```python
import time
from policyshield.core.models import RuleSet, RuleConfig, Verdict, ChainCondition
from policyshield.shield.matcher import MatcherEngine
from policyshield.shield.ring_buffer import EventRingBuffer


def _make_ruleset(rules):
    return RuleSet(shield_name="test", version="1", rules=rules, default_verdict=Verdict.ALLOW)


def test_chain_match_satisfied():
    """Chain rule matches when all conditions are in buffer."""
    rules = _make_ruleset([
        RuleConfig(
            id="anti-exfil",
            when={"tool": "send_email"},
            verdict=Verdict.BLOCK,
            chain=[ChainCondition(tool="read_database", within_seconds=60)],
        ),
    ])
    matcher = MatcherEngine(rules)

    buf = EventRingBuffer()
    buf.add("read_database", "allow")  # Добавляем событие

    matches = matcher.find_matching_rules("send_email", event_buffer=buf)
    assert len(matches) == 1
    assert matches[0].verdict == Verdict.BLOCK


def test_chain_match_not_satisfied():
    """Chain rule does NOT match when condition is missing from buffer."""
    rules = _make_ruleset([
        RuleConfig(
            id="anti-exfil",
            when={"tool": "send_email"},
            verdict=Verdict.BLOCK,
            chain=[ChainCondition(tool="read_database", within_seconds=60)],
        ),
    ])
    matcher = MatcherEngine(rules)

    buf = EventRingBuffer()  # Empty buffer

    matches = matcher.find_matching_rules("send_email", event_buffer=buf)
    assert len(matches) == 0  # Chain not satisfied → no match


def test_chain_multiple_conditions():
    """All chain conditions must be satisfied."""
    rules = _make_ruleset([
        RuleConfig(
            id="multi-chain",
            when={"tool": "send_email"},
            verdict=Verdict.BLOCK,
            chain=[
                ChainCondition(tool="read_database", within_seconds=60),
                ChainCondition(tool="query_secrets", within_seconds=120),
            ],
        ),
    ])
    matcher = MatcherEngine(rules)

    buf = EventRingBuffer()
    buf.add("read_database", "allow")
    # Missing query_secrets

    matches = matcher.find_matching_rules("send_email", event_buffer=buf)
    assert len(matches) == 0  # Partial chain → no match

    buf.add("query_secrets", "allow")
    matches = matcher.find_matching_rules("send_email", event_buffer=buf)
    assert len(matches) == 1  # All conditions met


def test_no_chain_backward_compatible():
    """Rules without chain should work as before."""
    rules = _make_ruleset([
        RuleConfig(id="basic", when={"tool": "read_file"}, verdict=Verdict.ALLOW),
    ])
    matcher = MatcherEngine(rules)

    matches = matcher.find_matching_rules("read_file")
    assert len(matches) == 1


def test_chain_with_verdict_filter():
    """Chain condition can filter by verdict."""
    rules = _make_ruleset([
        RuleConfig(
            id="chain-verdict",
            when={"tool": "send_email"},
            verdict=Verdict.BLOCK,
            chain=[ChainCondition(tool="read_file", within_seconds=60, verdict="allow")],
        ),
    ])
    matcher = MatcherEngine(rules)

    buf = EventRingBuffer()
    buf.add("read_file", "block")  # Wrong verdict

    matches = matcher.find_matching_rules("send_email", event_buffer=buf)
    assert len(matches) == 0

    buf.add("read_file", "allow")  # Right verdict
    matches = matcher.find_matching_rules("send_email", event_buffer=buf)
    assert len(matches) == 1
```

## Самопроверка

```bash
pytest tests/test_chain_matcher.py -v
pytest tests/ -q
```

## Коммит

```
feat(matcher): add chain condition matching for temporal rules

- Add _check_chain() to MatcherEngine
- Integrate chain check into _matches() pipeline
- Pass event_buffer through find_matching_rules/find_best_match
- All chain conditions must be satisfied (AND logic)
- Backward compatible: rules without chain work unchanged
```
