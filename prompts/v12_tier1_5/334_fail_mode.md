# Prompt 334 — Fail-Open / Fail-Closed Configuration

## Цель

Сделать fail-mode конфигурируемым: при ошибке engine → `ALLOW` (fail-open) или `BLOCK` (fail-closed).

## Контекст

- `base_engine.py` — `_fail_open: bool` уже есть, но не задаётся через env
- Prompt 301 использует `_fail_open` в error handler — нужно гарантировать правильную инициализацию
- Нужно: `POLICYSHIELD_FAIL_MODE=open|closed` (default: `closed`)

## Что сделать

```python
# base_engine.py — обновить __init__:
class BaseShieldEngine:
    def __init__(self, ...):
        fail_mode = os.environ.get("POLICYSHIELD_FAIL_MODE", "closed").lower()
        self._fail_open = (fail_mode == "open")
        logger.info("Fail mode: %s", "open (ALLOW on error)" if self._fail_open else "closed (BLOCK on error)")
```

```python
# Обновить check() для использования:
async def check(self, tool_name, args, **kwargs):
    try:
        return await self._perform_check(tool_name, args, **kwargs)
    except Exception as e:
        logger.error("Engine error: %s", e, exc_info=True)
        verdict = Verdict.ALLOW if self._fail_open else Verdict.BLOCK
        return ShieldResult(verdict=verdict, message=f"Engine error: {type(e).__name__}")
```

## Тесты

```python
class TestFailMode:
    def test_fail_closed_by_default(self):
        from policyshield.shield.sync_engine import ShieldEngine
        engine = ShieldEngine(rules="tests/fixtures/rules.yaml")
        assert engine._fail_open is False

    def test_fail_open_from_env(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_FAIL_MODE", "open")
        from policyshield.shield.sync_engine import ShieldEngine
        engine = ShieldEngine(rules="tests/fixtures/rules.yaml")
        assert engine._fail_open is True

    def test_fail_closed_blocks_on_error(self):
        # Mock engine to raise, verify BLOCK verdict
        pass

    def test_fail_open_allows_on_error(self):
        # Mock engine to raise, verify ALLOW verdict
        pass
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestFailMode -v
pytest tests/ -q
```

## Коммит

```
feat(engine): make fail-open/fail-closed configurable via POLICYSHIELD_FAIL_MODE
```
