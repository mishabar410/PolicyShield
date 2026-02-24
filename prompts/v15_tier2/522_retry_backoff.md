# 522 — Retry / Backoff for Notifications

## Goal

Add exponential backoff retry for Telegram and webhook approval notifications.

## Context

- Telegram API can return 429 (rate limit) or 5xx errors
- Webhooks can fail due to network issues
- 3 retries with exponential backoff (1s, 2s, 4s) before giving up

## Code

### New file: `policyshield/approval/retry.py`

```python
"""Retry with exponential backoff for approval notifications."""
import asyncio
import logging

logger = logging.getLogger(__name__)

async def retry_with_backoff(
    fn,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    retryable_exceptions: tuple = (Exception,),
):
    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except retryable_exceptions as e:
            if attempt == max_retries:
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            logger.warning("Retry %d/%d after %.1fs: %s", attempt + 1, max_retries, delay, e)
            await asyncio.sleep(delay)
```

### Modify: `policyshield/approval/telegram.py`

Wrap `_send_message()` and `_edit_message()` with `retry_with_backoff`.

### Modify: `policyshield/approval/webhook.py` (if exists)

Same treatment for webhook HTTP calls.

## Tests

- Test success on first attempt → no retry
- Test success on 2nd attempt → 1 retry
- Test failure after max retries → raises
- Test backoff delays are correct (mock `asyncio.sleep`)

## Self-check

```bash
pytest tests/test_retry_backoff.py -v
```

## Commit

```
feat: add retry with exponential backoff for approval notifications
```
