# Prompt 107 — Chain Integration

## Цель

Интегрировать chain matching в engine pipeline: прокинуть `event_buffer` из `SessionState` в matcher, записывать события после каждого check, добавить lint-проверку chain rules.

## Контекст

- `EventRingBuffer` живёт в `SessionState.event_buffer` (промпт 104)
- `ChainCondition` парсится из YAML (промпт 105)
- `MatcherEngine._matches()` умеет проверять chain (промпт 106)
- `ShieldEngine._do_check_sync()` (`shield/base_engine.py`) — основной pipeline
- После check нужно записать событие в buffer: `(tool, verdict)`
- CLI `lint` должна предупреждать о chain rules без matching outgoing tools

## Что сделать

### 1. Обновить `ShieldEngine._do_check_sync()`

В `shield/base_engine.py`:

```python
def _do_check_sync(self, tool_name: str, args: dict, session_id: str, sender: str | None) -> ShieldResult:
    session = self.session_manager.get_or_create(session_id)

    # Get event buffer for chain matching
    event_buffer = session.event_buffer

    # ... existing taint check (if any) ...

    # Find matching rule — now with event_buffer
    match = self._matcher.find_best_match(
        tool_name=tool_name,
        args=args,
        session_state=self._session_state_dict(session),
        sender=sender,
        event_buffer=event_buffer,  # NEW: pass buffer for chain matching
    )

    # ... existing logic to build ShieldResult ...

    # Record event in ring buffer AFTER verdict is determined
    event_buffer.add(tool_name, result.verdict.value, args_summary=str(args)[:200])

    # ... existing increment, trace recording, etc. ...
    return result
```

> **Важно:** событие записывается **после** определения verdict, чтобы текущий вызов не влиял на свой собственный chain match.

### 2. Конфигурация размера буфера

В YAML конфигурации:

```yaml
version: "1"
default_verdict: allow

session:
  event_buffer_size: 200  # default: 100
```

В `ShieldEngine.__init__()`:

```python
buffer_size = self.rule_set.config.get("session", {}).get("event_buffer_size", 100)
self.session_manager = SessionManager(
    ttl_seconds=...,
    max_sessions=...,
    event_buffer_size=buffer_size,  # Pass to SessionManager
)
```

### 3. Добавить chain rule lint проверку

В CLI lint (или создать `cli/lint.py` если нет):

```python
def lint_chain_rules(rule_set: RuleSet) -> list[str]:
    """Check chain rules for potential issues."""
    warnings = []

    for rule in rule_set.rules:
        if not rule.chain:
            continue

        # Check: chain rule without a specific tool match
        if not rule.when.get("tool"):
            warnings.append(
                f"Rule '{rule.id}': chain conditions defined but no 'tool' in 'when'. "
                f"Chain will apply to ALL tools — is this intentional?"
            )

        # Check: very long time windows (> 1 hour)
        for cond in rule.chain:
            if cond.within_seconds > 3600:
                warnings.append(
                    f"Rule '{rule.id}': chain condition for '{cond.tool}' has "
                    f"within_seconds={cond.within_seconds} (>{1}h). "
                    f"Consider reducing or increasing event_buffer_size."
                )

        # Check: chain references itself
        rule_tool = rule.when.get("tool", "")
        for cond in rule.chain:
            if cond.tool == rule_tool:
                warnings.append(
                    f"Rule '{rule.id}': chain condition references same tool '{cond.tool}' "
                    f"as the rule trigger. This may cause unexpected behavior."
                )

    return warnings
```

### 4. Документация

Добавить в `docs/rules.md` (или создать):

```markdown
## Chain Rules (Temporal Conditions)

Chain rules let you define policies based on tool call sequences:

\```yaml
rules:
  - id: anti-exfiltration
    when:
      tool: send_email
      chain:
        - tool: read_database
          within_seconds: 60
    then: block
    message: "Potential data exfiltration: database was read before sending email"
\```

### Semantics

- The rule triggers when `send_email` is called **AND** `read_database` was called within the last 60 seconds.
- Multiple chain conditions use AND logic — all must be satisfied.
- Chain checks use the session's event buffer (default: last 100 events).

### Use Cases

| Pattern | Description |
|---------|-------------|
| Anti-exfiltration | Block outgoing calls after sensitive data access |
| Rate-limiting sequences | Block rapid repeated patterns |
| Approval escalation | Require approval if dangerous tool called after another |
```

### 5. Тесты

#### `tests/test_chain_integration.py`

```python
from policyshield.core.models import Verdict
from policyshield.core.parser import parse_rules_from_string
from policyshield.shield.base_engine import ShieldEngine


def test_chain_rule_blocks_exfiltration():
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: anti-exfil
    when:
      tool: send_email
      chain:
        - tool: read_database
          within_seconds: 60
    then: block
    message: "Exfiltration blocked"
"""
    engine = ShieldEngine(rules_text=yaml_text)

    # First call: read_database → ALLOW (no chain rule for this tool)
    r1 = engine.check("read_database", {"query": "SELECT *"}, session_id="s1")
    assert r1.verdict == Verdict.ALLOW

    # Second call: send_email → BLOCK (chain condition satisfied: read_database was recent)
    r2 = engine.check("send_email", {"to": "attacker@evil.com"}, session_id="s1")
    assert r2.verdict == Verdict.BLOCK
    assert "exfiltration" in r2.message.lower()


def test_chain_rule_allows_when_no_prior():
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: anti-exfil
    when:
      tool: send_email
      chain:
        - tool: read_database
          within_seconds: 60
    then: block
"""
    engine = ShieldEngine(rules_text=yaml_text)

    # send_email without prior read_database → ALLOW (chain not satisfied)
    r = engine.check("send_email", {"to": "friend@company.com"}, session_id="s1")
    assert r.verdict == Verdict.ALLOW


def test_chain_different_sessions_independent():
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: anti-exfil
    when:
      tool: send_email
      chain:
        - tool: read_database
          within_seconds: 60
    then: block
"""
    engine = ShieldEngine(rules_text=yaml_text)

    # Session 1: read_database
    engine.check("read_database", {}, session_id="s1")

    # Session 2: send_email → ALLOW (different session, no read_database)
    r = engine.check("send_email", {"to": "x@y.com"}, session_id="s2")
    assert r.verdict == Verdict.ALLOW


def test_lint_chain_self_reference(capsys):
    from policyshield.core.parser import parse_rules_from_string
    # Этот тест проверяет lint-предупреждение для chain, ссылающегося сам на себя
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: self-ref
    when:
      tool: send_email
      chain:
        - tool: send_email
          within_seconds: 10
    then: block
"""
    rule_set = parse_rules_from_string(yaml_text)
    from policyshield.cli.lint import lint_chain_rules  # or wherever it lives
    warnings = lint_chain_rules(rule_set)
    assert any("same tool" in w for w in warnings)
```

## Самопроверка

```bash
pytest tests/test_chain_integration.py -v
pytest tests/ -q
```

## Коммит

```
feat(engine): integrate chain rules into check pipeline

- Pass event_buffer from SessionState to MatcherEngine
- Record tool events in buffer after each check
- Configurable event_buffer_size in YAML
- Add lint warnings for chain rules (self-reference, long windows)
- Add chain rules documentation
- E2E test: anti-exfiltration scenario (read_db → send_email → BLOCK)
```
