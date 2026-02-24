# 533 — Slack / Webhook Notifications

## Goal

Add Slack and generic webhook approval backends.

## Context

- Currently: Telegram and InMemory backends
- Slack is the most popular team chat for engineering
- Webhooks enable custom integrations (Discord, PagerDuty, etc.)

## Code

### New file: `policyshield/approval/slack.py`

```python
"""Slack approval backend — sends interactive messages for human approval."""
import httpx

class SlackApprovalBackend(ApprovalBackendBase):
    def __init__(self, webhook_url: str, channel: str | None = None):
        self._webhook_url = webhook_url
        self._channel = channel

    async def request_approval(self, request: ApprovalRequest) -> str:
        payload = {
            "text": f"🛡️ PolicyShield: approve `{request.tool_name}`?",
            "attachments": [{
                "text": f"Args: {request.args}\nSession: {request.session_id}",
                "callback_id": request.approval_id,
                "actions": [
                    {"name": "approve", "text": "✅ Approve", "type": "button", "value": "approve"},
                    {"name": "deny", "text": "❌ Deny", "type": "button", "value": "deny"},
                ],
            }],
        }
        async with httpx.AsyncClient() as client:
            await client.post(self._webhook_url, json=payload)
        return request.approval_id
```

### New file: `policyshield/approval/webhook.py`

```python
"""Generic webhook approval backend — POST to any URL."""
class WebhookApprovalBackend(ApprovalBackendBase):
    def __init__(self, url: str, headers: dict | None = None):
        self._url = url
        self._headers = headers or {}

    async def request_approval(self, request: ApprovalRequest) -> str:
        payload = request.to_dict()
        async with httpx.AsyncClient() as client:
            await client.post(self._url, json=payload, headers=self._headers)
        return request.approval_id
```

### Config support

`POLICYSHIELD_SLACK_WEBHOOK_URL` env var → auto-configure Slack backend.

## Tests

- Test Slack payload format
- Test webhook sends correct POST
- Test fallback when webhook fails

## Self-check

```bash
ruff check policyshield/approval/slack.py policyshield/approval/webhook.py
pytest tests/test_slack_approval.py tests/test_webhook_approval.py -v
```

## Commit

```
feat: add Slack and generic webhook approval backends
```
