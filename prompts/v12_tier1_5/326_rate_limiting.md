# Prompt 326 — Rate Limiting

## Цель

Добавить rate limiting для auth endpoints (`/reload`, `/kill-switch`), чтобы предотвратить brute-force.

## Контекст

- Мутирующие endpoints защищены token, но нет rate limiting → brute-force token
- Нужно: 10 req/min per IP для admin endpoints
- Для `/check` rate limiting не нужен (backpressure из #307 достаточно)

## Что сделать

### 1. Simple in-memory rate limiter

```python
# server/rate_limiter.py
from collections import defaultdict
from time import monotonic
import threading

class InMemoryRateLimiter:
    """Simple token-bucket rate limiter per key."""

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0):
        self._max = max_requests
        self._window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = monotonic()
        with self._lock:
            self._requests[key] = [t for t in self._requests[key] if now - t < self._window]
            if len(self._requests[key]) >= self._max:
                return False
            self._requests[key].append(now)
            return True
```

### 2. Middleware в `app.py`

```python
_admin_limiter = InMemoryRateLimiter(max_requests=10, window_seconds=60)

@app.middleware("http")
async def rate_limit_admin(request: Request, call_next):
    admin_paths = ("/api/v1/reload", "/api/v1/kill-switch")
    if any(request.url.path.startswith(p) for p in admin_paths):
        client_ip = request.client.host if request.client else "unknown"
        if not _admin_limiter.is_allowed(client_ip):
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited", "message": "Too many requests"},
            )
    return await call_next(request)
```

## Тесты

```python
class TestRateLimiting:
    def test_within_limit_allowed(self):
        from policyshield.server.rate_limiter import InMemoryRateLimiter
        rl = InMemoryRateLimiter(max_requests=3, window_seconds=60)
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is True

    def test_over_limit_rejected(self):
        rl = InMemoryRateLimiter(max_requests=2, window_seconds=60)
        rl.is_allowed("ip1")
        rl.is_allowed("ip1")
        assert rl.is_allowed("ip1") is False

    def test_different_keys_independent(self):
        rl = InMemoryRateLimiter(max_requests=1, window_seconds=60)
        rl.is_allowed("ip1")
        assert rl.is_allowed("ip2") is True

    def test_window_resets(self):
        rl = InMemoryRateLimiter(max_requests=1, window_seconds=0.1)
        rl.is_allowed("ip1")
        import time; time.sleep(0.15)
        assert rl.is_allowed("ip1") is True
```

## Самопроверка

```bash
pytest tests/test_security_data.py::TestRateLimiting -v
pytest tests/ -q
```

## Коммит

```
feat(server): add rate limiting for admin endpoints (10 req/min per IP)
```
