# Prompt 352 — Retry / Exponential Backoff in SDK

## Цель

Добавить retry с exponential backoff в `PolicyShieldClient` для 5xx и network ошибок.

## Контекст

- Без retry: транзиентная ошибка (overload, network glitch) → BLOCK/crash
- Нужно: retry 3 раза с backoff 0.5s, 1s, 2s; retry на 5xx и `ConnectionError`

## Что сделать

```python
# policyshield/client.py — обновить:
import time

class PolicyShieldClient:
    def __init__(self, ..., max_retries: int = 3, backoff_factor: float = 0.5):
        self._max_retries = max_retries
        self._backoff = backoff_factor

    def _request(self, method: str, path: str, **kwargs):
        last_exc = None
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._client.request(method, path, **kwargs)
                if resp.status_code < 500:
                    return resp
                last_exc = httpx.HTTPStatusError(f"{resp.status_code}", request=resp.request, response=resp)
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_exc = e
            if attempt < self._max_retries:
                delay = self._backoff * (2 ** attempt)
                time.sleep(delay)
        raise last_exc  # All retries exhausted
```

## Тесты

```python
class TestRetryBackoff:
    def test_retries_on_500(self, httpx_mock):
        httpx_mock.add_response(status_code=500)
        httpx_mock.add_response(status_code=500)
        httpx_mock.add_response(json={"verdict": "ALLOW"})
        # Should succeed after 2 retries
        pass

    def test_no_retry_on_400(self, httpx_mock):
        # 400 errors should NOT be retried
        pass

    def test_max_retries_exhausted(self, httpx_mock):
        # All retries fail → raises
        pass
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestRetryBackoff -v
pytest tests/ -q
```

## Коммит

```
feat(sdk): add retry with exponential backoff (3 retries, 5xx/network)
```
