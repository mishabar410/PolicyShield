# Prompt 337 — Startup Self-Test

## Цель

При старте сервера выполнить self-test: загрузить правила, прогнать dummy check, убедиться что engine работает.

## Контекст

- Сервер стартует, но может иметь broken rules / missing dependencies
- Нужно: при старте → dummy `engine.check("__self_test__", {})` → если crash → fail-fast
- Связано с `policyshield doctor` (v11), но здесь — внутренний check в lifespan

## Что сделать

```python
# app.py — в lifespan, после existing startup:
async def _startup_self_test(engine: AsyncShieldEngine):
    """Run a quick self-test to verify engine is operational."""
    try:
        result = await engine.check("__self_test__", {})
        logger.info("Startup self-test passed: verdict=%s", result.verdict.value)
    except Exception as e:
        logger.critical("Startup self-test FAILED: %s", e)
        raise RuntimeError(f"Engine self-test failed: {e}") from e

# В lifespan:
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await _startup_self_test(engine)
    yield
    # Shutdown ...
```

## Тесты

```python
class TestStartupSelfTest:
    @pytest.mark.asyncio
    async def test_self_test_passes_with_valid_engine(self):
        from policyshield.server.app import _startup_self_test
        # Create valid engine → self-test should pass
        pass

    @pytest.mark.asyncio
    async def test_self_test_fails_with_broken_engine(self):
        # Create engine that crashes → self-test should raise
        pass
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestStartupSelfTest -v
pytest tests/ -q
```

## Коммит

```
feat(server): add startup self-test (fail-fast on broken engine)
```
