# Prompt 359 — Idempotency Key

## Цель

Поддержать idempotency key в `/check`: одинаковый запрос с тем же ключом → кешированный ответ.

## Контекст

- Retry (SDK, network) может отправить один и тот же check дважды
- Нужно: если `x-idempotency-key` совпадает → вернуть кешированный результат
- TTL cache: 5 мин, max 10K entries

## Что сделать

```python
# server/idempotency.py
from collections import OrderedDict
import threading

class IdempotencyCache:
    def __init__(self, max_size: int = 10_000, ttl: float = 300.0):
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl
        self._lock = threading.Lock()

    def get(self, key: str) -> dict | None:
        with self._lock:
            if key in self._cache:
                ts, result = self._cache[key]
                from time import monotonic
                if monotonic() - ts < self._ttl:
                    return result
                del self._cache[key]
        return None

    def set(self, key: str, result: dict):
        from time import monotonic
        with self._lock:
            self._cache[key] = (monotonic(), result)
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)
```

```python
# app.py — в check handler:
_idem_cache = IdempotencyCache()

@app.post("/api/v1/check")
async def check(req: CheckRequest, request: Request):
    idem_key = request.headers.get("x-idempotency-key")
    if idem_key:
        cached = _idem_cache.get(idem_key)
        if cached:
            return JSONResponse(content=cached)
    # ... normal check ...
    if idem_key:
        _idem_cache.set(idem_key, response_dict)
```

## Тесты

```python
class TestIdempotency:
    def test_same_key_returns_cached(self, client):
        headers = {"x-idempotency-key": "test-key-1"}
        r1 = client.post("/api/v1/check", json={"tool_name": "test"}, headers=headers)
        r2 = client.post("/api/v1/check", json={"tool_name": "test"}, headers=headers)
        assert r1.json() == r2.json()

    def test_different_keys_independent(self, client):
        r1 = client.post("/api/v1/check", json={"tool_name": "test"}, headers={"x-idempotency-key": "k1"})
        r2 = client.post("/api/v1/check", json={"tool_name": "other"}, headers={"x-idempotency-key": "k2"})
        # Different requests, different keys → independent results

    def test_no_key_no_caching(self, client):
        # Without idempotency key, no caching behavior
        pass
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestIdempotency -v
pytest tests/ -q
```

## Коммит

```
feat(server): add idempotency key support (x-idempotency-key header)
```
