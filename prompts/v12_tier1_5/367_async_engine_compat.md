# Prompt 367 — AsyncShieldEngine Wrapper

## Цель

Убедиться, что `AsyncShieldEngine` полностью поддерживает все новые фичи из Tier 1.5 (timeout, fail-mode, cleanup), и синхронизировать с `ShieldEngine`.

## Контекст

- Многие Tier 1.5 фичи добавлены в `BaseShieldEngine` / sync engine
- `AsyncShieldEngine` наследуется от `BaseShieldEngine`, но может пропустить async-specific адаптации
- Нужно: проверить и адаптировать async-обёртки для всех новых возможностей

## Что сделать

### 1. Проверить что async engine подхватывает:
- `_fail_open` → из `BaseShieldEngine.__init__()` (✓ наследуется)
- `_cleanup_approval_meta()` → вызывается из `_handle_approval_sync()` (✓ наследуется)
- Engine timeout → `asyncio.wait_for()` уже в async check (✓)
- Config validation → вызывается в lifespan (✓ не engine-specific)

### 2. Добавить async-specific tests

```python
class TestAsyncEngineCompat:
    @pytest.mark.asyncio
    async def test_async_engine_has_fail_open(self):
        from policyshield.shield.async_engine import AsyncShieldEngine
        engine = AsyncShieldEngine(rules="tests/fixtures/rules.yaml")
        assert hasattr(engine, '_fail_open')

    @pytest.mark.asyncio
    async def test_async_check_with_timeout(self):
        engine = AsyncShieldEngine(rules="tests/fixtures/rules.yaml")
        result = await engine.check("test_tool", {})
        assert result.verdict is not None

    @pytest.mark.asyncio
    async def test_async_approval_meta_cleanup(self):
        engine = AsyncShieldEngine(rules="tests/fixtures/rules.yaml")
        assert hasattr(engine, '_cleanup_approval_meta')
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestAsyncEngineCompat -v
pytest tests/ -q
```

## Коммит

```
test(engine): add async engine compatibility tests for Tier 1.5 features
```
