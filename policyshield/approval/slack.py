"""Slack approval backend — sends messages to Slack for human approval."""

from __future__ import annotations

import logging
from typing import Any

from policyshield.approval.base import ApprovalBackend, ApprovalRequest, ApprovalResponse

logger = logging.getLogger(__name__)

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class SlackApprovalBackend(ApprovalBackend):
    """Approval backend that sends approval requests to Slack via webhook.

    Uses Slack Incoming Webhooks to post approval notifications.
    Responses are received via the REST API and stored in-memory.

    Args:
        webhook_url: Slack Incoming Webhook URL.
        channel: Optional channel override.
    """

    def __init__(self, webhook_url: str, channel: str | None = None) -> None:
        if not HAS_HTTPX:
            raise ImportError("Slack backend requires httpx: pip install httpx")
        self._webhook_url = webhook_url
        self._channel = channel
        # Delegate storage to InMemoryBackend
        from policyshield.approval.memory import InMemoryBackend

        self._store = InMemoryBackend()

    def submit(self, request: ApprovalRequest) -> None:
        """Submit request — store in memory and notify Slack."""
        self._store.submit(request)
        self._send_slack_notification(request)

    def wait_for_response(self, request_id: str, timeout: float = 300.0) -> ApprovalResponse | None:
        return self._store.wait_for_response(request_id, timeout)

    def respond(self, request_id: str, approved: bool, responder: str = "", comment: str = "") -> None:
        self._store.respond(request_id, approved, responder, comment)

    def pending(self) -> list[ApprovalRequest]:
        return self._store.pending()

    def _send_slack_notification(self, request: ApprovalRequest) -> None:
        """Send Slack notification for an approval request."""
        import json as _json

        args_preview = _json.dumps(request.args, indent=2, default=str)
        if len(args_preview) > 500:
            args_preview = args_preview[:500] + "\n..."

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🛡️ PolicyShield Approval Request"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:* `{request.tool_name}`"},
                    {"type": "mrkdwn", "text": f"*Session:* `{request.session_id}`"},
                    {"type": "mrkdwn", "text": f"*ID:* `{request.request_id}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Args:*\n```{args_preview}```"},
            },
        ]

        payload: dict[str, Any] = {"blocks": blocks}
        if self._channel:
            payload["channel"] = self._channel

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(self._webhook_url, json=payload)
                resp.raise_for_status()
            logger.info("Slack notification sent for approval %s", request.request_id)
        except Exception:
            logger.warning("Failed to send Slack notification for %s", request.request_id)

    def health(self) -> dict[str, Any]:
        return {"healthy": True, "backend": "slack", "webhook_configured": bool(self._webhook_url)}
