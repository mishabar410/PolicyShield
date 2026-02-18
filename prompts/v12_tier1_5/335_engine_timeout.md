# Prompt 335 — Engine Check Timeout

## Цель

Добавить per-check таймаут внутри engine, чтобы одно правило с regex backtracking не залочило весь процесс.

## Контекст

- HTTP timeout (#308) ловит медленные запросы, но engine-level timeout нужен для более точного контроля
- `base_engine.py` → `_match_rules()` вызывает `re.search()` для каждого правила — потенциальный ReDoS
- Нужно: per-check timeout (default 5s), отдельно от HTTP timeout

## Что сделать

```python
# base_engine.py
import asyncio

ENGINE_CHECK_TIMEOUT = float(os.environ.get("POLICYSHIELD_ENGINE_TIMEOUT", 5.0))

async def check(self, tool_name, args, **kwargs):
    try:
        return await asyncio.wait_for(
            self._perform_check(tool_name, args, **kwargs),
            timeout=ENGINE_CHECK_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.error("Engine check timeout (%.1fs) for tool=%s", ENGINE_CHECK_TIMEOUT, tool_name)
        verdict = Verdict.ALLOW if self._fail_open else Verdict.BLOCK
        return ShieldResult(verdict=verdict, message="Check timed out")
```

## Тесты

```python
class TestEngineTimeout:
    @pytest.mark.asyncio
    async def test_slow_check_times_out(self):
        # Create engine with very slow rule (or mock)
        # Verify timeout verdict
        pass

    @pytest.mark.asyncio
    async def test_fast_check_succeeds(self):
        # Normal check completes within timeout
        pass
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestEngineTimeout -v
pytest tests/ -q
```

## Коммит

```
feat(engine): add per-check timeout (default 5s, POLICYSHIELD_ENGINE_TIMEOUT)
```
