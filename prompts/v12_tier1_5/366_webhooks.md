# Prompt 366 — Webhook Notifications

## Цель

Добавить webhook уведомления при BLOCK/APPROVE verdicts → отправка JSON на указанный URL.

## Контекст

- Для alerting: Slack, PagerDuty, custom → нужен generic webhook
- Env: `POLICYSHIELD_WEBHOOK_URL`, `POLICYSHIELD_WEBHOOK_EVENTS=BLOCK,APPROVE`

## Что сделать

```python
# server/webhook.py
import httpx
import logging
import asyncio
from typing import Any

logger = logging.getLogger(__name__)

class WebhookNotifier:
    def __init__(self, url: str, events: list[str] | None = None, timeout: float = 5.0):
        self._url = url
        self._events = set(events or ["BLOCK", "APPROVE"])
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def notify(self, verdict: str, tool_name: str, details: dict[str, Any]):
        if verdict not in self._events:
            return
        payload = {
            "event": "policy_check",
            "verdict": verdict,
            "tool_name": tool_name,
            **details,
        }
        try:
            resp = await self._client.post(self._url, json=payload)
            logger.debug("Webhook sent: %s → %d", self._url, resp.status_code)
        except Exception as e:
            logger.warning("Webhook failed: %s", e)

    async def close(self):
        await self._client.aclose()
```

### Интеграция

```python
# app.py — в check handler, после result:
if _webhook and result.verdict.value in _webhook._events:
    asyncio.create_task(_webhook.notify(result.verdict.value, req.tool_name, {"request_id": req_id}))
```

## Тесты

```python
class TestWebhook:
    @pytest.mark.asyncio
    async def test_webhook_fires_on_block(self, httpx_mock):
        httpx_mock.add_response()
        from policyshield.server.webhook import WebhookNotifier
        wh = WebhookNotifier(url="https://example.com/webhook", events=["BLOCK"])
        await wh.notify("BLOCK", "dangerous_tool", {"request_id": "r1"})
        assert len(httpx_mock.get_requests()) == 1

    @pytest.mark.asyncio
    async def test_webhook_skips_allow(self, httpx_mock):
        from policyshield.server.webhook import WebhookNotifier
        wh = WebhookNotifier(url="https://example.com/webhook", events=["BLOCK"])
        await wh.notify("ALLOW", "safe_tool", {})
        assert len(httpx_mock.get_requests()) == 0
```

## Коммит

```
feat(server): add webhook notifications for BLOCK/APPROVE verdicts
```
