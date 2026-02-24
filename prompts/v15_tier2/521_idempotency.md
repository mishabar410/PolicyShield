# 521 — Idempotency / Request Dedup

## Goal

Add `idempotency_key` to check requests. Repeated requests with the same key return cached results.

## Context

- Agents may retry the same tool call multiple times
- Without dedup, each retry creates a separate approval request
- LRU cache with configurable TTL avoids duplicate work

## Code

### Modify: `policyshield/server/models.py`

Add `idempotency_key: str | None = None` to `CheckRequest`.

### Modify: `policyshield/server/app.py`

```python
from functools import lru_cache
from cachetools import TTLCache

_idempotency_cache = TTLCache(maxsize=10_000, ttl=300)  # 5 min

# In check handler:
if request.idempotency_key:
    cached = _idempotency_cache.get(request.idempotency_key)
    if cached:
        return cached
# ... do check ...
if request.idempotency_key:
    _idempotency_cache[request.idempotency_key] = response
```

### Modify: `plugins/openclaw/src/types.ts`

Add `idempotency_key?: string` to `CheckRequest`.

## Tests

- Test duplicate key returns same result
- Test different keys return independent results
- Test cache expires after TTL
- Test None key = no caching

## Self-check

```bash
pytest tests/test_idempotency.py -v
python scripts/check_sdk_sync.py
```

## Commit

```
feat: add idempotency_key support for request deduplication
```
