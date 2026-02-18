# Prompt 336 — Atomic Hot-Reload

## Цель

Сделать hot-reload атомарным: validate → swap (old rules работают до полной замены).

## Контекст

- `base_engine.py` — `reload_rules()` парсит YAML и **сразу** заменяет `_rules`
- Если новый YAML невалиден → engine в broken state (пустые правила)
- Нужно: parse + validate новых правил ДО замены старых

## Что сделать

```python
# base_engine.py — обновить reload_rules():
def reload_rules(self, path: str | None = None):
    """Atomically reload rules: validate first, then swap."""
    source = path or self._rules_path
    logger.info("Reloading rules from %s", source)

    try:
        # 1. Parse and validate NEW rules (without modifying state)
        new_ruleset = self._load_rules(source)
        new_count = len(new_ruleset.rules)

        # 2. Validate: each rule must have required fields
        for rule in new_ruleset.rules:
            if not rule.tool_name:
                raise ValueError(f"Rule {rule.id} missing tool_name")

        # 3. Atomic swap
        old_count = self.rule_count
        self._ruleset = new_ruleset
        self._rules_path = source

        logger.info("Rules reloaded: %d → %d rules", old_count, new_count)
        return {"old_count": old_count, "new_count": new_count}

    except Exception as e:
        logger.error("Reload failed (keeping old rules): %s", e)
        raise  # Caller handles; old rules remain active
```

## Тесты

```python
class TestAtomicHotReload:
    def test_valid_reload_swaps_rules(self, engine, tmp_path):
        # Write new valid rules → reload → verify new rules active
        pass

    def test_invalid_reload_keeps_old_rules(self, engine, tmp_path):
        old_count = engine.rule_count
        invalid_yaml = tmp_path / "bad.yaml"
        invalid_yaml.write_text("!!invalid yaml [[[")
        with pytest.raises(Exception):
            engine.reload_rules(str(invalid_yaml))
        assert engine.rule_count == old_count  # Old rules still active

    def test_reload_with_invalid_rule_keeps_old(self, engine, tmp_path):
        # Rule missing tool_name → reload fails → old rules remain
        pass
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestAtomicHotReload -v
pytest tests/ -q
```

## Коммит

```
fix(engine): make hot-reload atomic (validate before swap)
```
