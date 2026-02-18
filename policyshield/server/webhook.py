"""Webhook notifications for BLOCK/APPROVE verdicts."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class WebhookNotifier:
    """Send JSON webhook on policy events (BLOCK, APPROVE)."""

    def __init__(
        self,
        url: str,
        events: list[str] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._url = url
        self._events = set(events or ["BLOCK", "APPROVE"])
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def notify(
        self,
        verdict: str,
        tool_name: str,
        details: dict[str, Any],
    ) -> None:
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

    async def close(self) -> None:
        await self._client.aclose()
