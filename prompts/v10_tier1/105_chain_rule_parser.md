# Prompt 105 — Chain Rule Parser

## Цель

Добавить поддержку `when.chain` в YAML-правилах — парсинг chain conditions (временных зависимостей между вызовами).

## Контекст

- Формат YAML-правил (`core/models.py`): `RuleConfig` с полем `when` (dict)
- Сейчас `when` содержит `tool`, `args`, `sender`
- Нужно добавить `when.chain` — список условий «если tool X был вызван в последние N секунд»
- Chain rule пример: «блокировать `send_email`, если `read_database` был вызван в последние 60 секунд»

## Формат YAML

```yaml
rules:
  - id: anti-exfiltration
    when:
      tool: send_email
      chain:
        - tool: read_database
          within_seconds: 60
        - tool: query_secrets
          within_seconds: 120
    then: block
    message: "Suspicious data exfiltration pattern detected"
```

Семантика: правило срабатывает если:
1. Текущий вызов — `send_email` (обычный `when.tool` match)
2. **И** в последние 60 сек был вызов `read_database`
3. **И** в последние 120 сек был вызов `query_secrets`

## Что сделать

### 1. Добавить `ChainCondition` в `core/models.py`

```python
@dataclass
class ChainCondition:
    """A temporal condition: tool X must have been called within N seconds."""
    tool: str
    within_seconds: float
    verdict: str | None = None  # Optional: only match if that call had this verdict
```

Добавить в `RuleConfig`:

```python
@dataclass
class RuleConfig:
    # ... existing fields ...
    chain: list[ChainCondition] = field(default_factory=list)
```

### 2. Обновить `core/parser.py`

В `_parse_rule()`, при парсинге `when`:

```python
def _parse_chain(chain_raw: list[dict] | None) -> list[ChainCondition]:
    """Parse chain conditions from YAML."""
    if not chain_raw:
        return []
    conditions = []
    for item in chain_raw:
        if not isinstance(item, dict):
            raise ValueError(f"Chain condition must be a dict, got {type(item)}")
        if "tool" not in item:
            raise ValueError("Chain condition must have 'tool' field")
        if "within_seconds" not in item:
            raise ValueError("Chain condition must have 'within_seconds' field")
        within = item["within_seconds"]
        if not isinstance(within, (int, float)) or within <= 0:
            raise ValueError(f"within_seconds must be a positive number, got {within}")
        conditions.append(ChainCondition(
            tool=item["tool"],
            within_seconds=float(within),
            verdict=item.get("verdict"),
        ))
    return conditions
```

Вызвать из `_parse_rule()`:

```python
chain = _parse_chain(when.get("chain"))
rule = RuleConfig(
    # ... existing ...
    chain=chain,
)
```

### 3. Валидация в `policyshield/cli/lint.py` (если есть) или в парсере

Добавить проверку:
- `chain` без `tool` → ошибка
- `chain[*].within_seconds` <= 0 → ошибка
- `chain` с пустым списком → предупреждение

### 4. Тесты

#### `tests/test_chain_parser.py`

```python
import pytest
from policyshield.core.parser import parse_rules_from_string


def test_parse_chain_rule():
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
        - tool: query_secrets
          within_seconds: 120
    then: block
    message: "Exfiltration detected"
"""
    rule_set = parse_rules_from_string(yaml_text)
    rule = rule_set.rules[0]
    assert len(rule.chain) == 2
    assert rule.chain[0].tool == "read_database"
    assert rule.chain[0].within_seconds == 60
    assert rule.chain[1].tool == "query_secrets"
    assert rule.chain[1].within_seconds == 120


def test_parse_rule_without_chain():
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: basic
    when:
      tool: read_file
    then: allow
"""
    rule_set = parse_rules_from_string(yaml_text)
    assert rule_set.rules[0].chain == []


def test_chain_missing_tool():
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: bad
    when:
      tool: send_email
      chain:
        - within_seconds: 60
    then: block
"""
    with pytest.raises(ValueError, match="tool"):
        parse_rules_from_string(yaml_text)


def test_chain_negative_seconds():
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: bad
    when:
      tool: send_email
      chain:
        - tool: read_file
          within_seconds: -10
    then: block
"""
    with pytest.raises(ValueError, match="positive"):
        parse_rules_from_string(yaml_text)


def test_chain_with_verdict_filter():
    yaml_text = """
version: "1"
default_verdict: allow
rules:
  - id: chain-verdict
    when:
      tool: send_email
      chain:
        - tool: read_file
          within_seconds: 30
          verdict: allow
    then: block
"""
    rule_set = parse_rules_from_string(yaml_text)
    assert rule_set.rules[0].chain[0].verdict == "allow"
```

## Самопроверка

```bash
pytest tests/test_chain_parser.py -v
pytest tests/ -q
```

## Коммит

```
feat(rules): add chain rule parsing — temporal conditions in YAML

- Add ChainCondition model: tool, within_seconds, verdict
- Parse `when.chain` list in YAML rules
- Validate: tool required, within_seconds > 0
- Default: empty chain list (backward compatible)
```
