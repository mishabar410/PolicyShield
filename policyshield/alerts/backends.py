"""Alert backends and dispatcher — Console, Webhook, Slack, Telegram delivery."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from policyshield.alerts import Alert

logger = logging.getLogger(__name__)


class AlertBackend(ABC):
    """Base class for alert delivery backends."""

    @abstractmethod
    def send(self, alert: Alert) -> bool:
        """Send an alert. Returns True on success."""


class ConsoleBackend(AlertBackend):
    """Prints alerts to console/logs."""

    def __init__(self, use_logger: bool = False) -> None:
        self._use_logger = use_logger

    def send(self, alert: Alert) -> bool:
        icon = {"CRITICAL": "🚨", "WARNING": "⚠️", "INFO": "ℹ️"}.get(alert.severity.value, "📌")
        msg = f"{icon} [{alert.severity.value}] {alert.rule_name}: {alert.message}"
        if self._use_logger:
            logger.warning(msg)
        else:
            print(msg)
        return True


class WebhookBackend(AlertBackend):
    """Sends alerts via HTTP POST to a webhook URL."""

    def __init__(self, url: str, headers: dict | None = None, timeout: int = 10) -> None:
        self._url = url
        self._headers = headers or {"Content-Type": "application/json"}
        self._timeout = timeout

    def send(self, alert: Alert) -> bool:
        import urllib.request

        payload = json.dumps(alert.to_dict()).encode()
        req = urllib.request.Request(self._url, data=payload, headers=self._headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            logger.error("Webhook send failed: %s", e)
            return False


class SlackBackend(AlertBackend):
    """Sends alerts to Slack via incoming webhook."""

    def __init__(self, webhook_url: str, channel: str | None = None) -> None:
        self._webhook_url = webhook_url
        self._channel = channel

    def send(self, alert: Alert) -> bool:
        import urllib.request

        icon = {"CRITICAL": ":rotating_light:", "WARNING": ":warning:", "INFO": ":information_source:"}.get(
            alert.severity.value, ":bell:"
        )
        payload: dict = {
            "text": f"{icon} *[{alert.severity.value}]* {alert.rule_name}\n{alert.message}",
        }
        if self._channel:
            payload["channel"] = self._channel

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self._webhook_url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            logger.error("Slack send failed: %s", e)
            return False


class TelegramBackend(AlertBackend):
    """Sends alerts to Telegram via Bot API."""

    def __init__(self, bot_token: str, chat_id: str) -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id

    def send(self, alert: Alert) -> bool:
        import urllib.parse
        import urllib.request

        icon = {"CRITICAL": "🚨", "WARNING": "⚠️", "INFO": "ℹ️"}.get(alert.severity.value, "📌")
        text = f"{icon} [{alert.severity.value}] {alert.rule_name}\n{alert.message}"
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
        params = urllib.parse.urlencode({"chat_id": self._chat_id, "text": text})
        try:
            with urllib.request.urlopen(f"{url}?{params}", timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            logger.error("Telegram send failed: %s", e)
            return False


@dataclass
class AlertDispatcher:
    """Dispatches alerts to multiple backends."""

    backends: list[AlertBackend] = field(default_factory=list)

    def add_backend(self, backend: AlertBackend) -> None:
        self.backends.append(backend)

    def dispatch(self, alerts: list[Alert]) -> dict[str, int]:
        """Send alerts to all backends. Returns {backend_class: success_count}."""
        results: dict[str, int] = {}
        for backend in self.backends:
            key = backend.__class__.__name__
            count = 0
            for alert in alerts:
                if backend.send(alert):
                    count += 1
            results[key] = count
        return results

    @staticmethod
    def from_config(config: dict) -> "AlertDispatcher":
        """Build dispatcher from config dict."""
        dispatcher = AlertDispatcher()

        backends_cfg = config.get("backends", [])
        for bcfg in backends_cfg:
            btype = bcfg.get("type", "")
            if btype == "console":
                dispatcher.add_backend(ConsoleBackend(use_logger=bcfg.get("use_logger", False)))
            elif btype == "webhook":
                dispatcher.add_backend(WebhookBackend(url=bcfg["url"], headers=bcfg.get("headers")))
            elif btype == "slack":
                dispatcher.add_backend(SlackBackend(webhook_url=bcfg["webhook_url"], channel=bcfg.get("channel")))
            elif btype == "telegram":
                dispatcher.add_backend(TelegramBackend(bot_token=bcfg["bot_token"], chat_id=bcfg["chat_id"]))

        return dispatcher
