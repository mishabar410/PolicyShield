"""Telegram Bot API approval backend."""

from __future__ import annotations

import logging
import threading

import httpx

from policyshield.approval.base import (
    ApprovalBackend,
    ApprovalRequest,
    ApprovalResponse,
)

logger = logging.getLogger(__name__)

_TELEGRAM_API = "https://api.telegram.org"


class TelegramApprovalBackend(ApprovalBackend):
    """Approval backend using Telegram Bot API.

    Sends approval requests as messages with inline keyboard buttons,
    then polls for callback query responses.

    Args:
        bot_token: Telegram Bot API token.
        chat_id: Telegram chat ID to send requests to.
        poll_interval: Seconds between polls for responses.
        api_base: Base URL for Telegram API (for testing).
    """

    def __init__(
        self,
        bot_token: str,
        chat_id: str | int,
        poll_interval: float = 2.0,
        api_base: str = _TELEGRAM_API,
    ) -> None:
        self._token = bot_token
        self._chat_id = str(chat_id)
        self._poll_interval = poll_interval
        self._api_base = api_base
        self._client = httpx.Client(timeout=30.0)

        self._pending: dict[str, ApprovalRequest] = {}
        self._responses: dict[str, ApprovalResponse] = {}
        self._events: dict[str, threading.Event] = {}
        self._message_ids: dict[str, int] = {}  # request_id -> telegram message_id
        self._lock = threading.Lock()

        # Offset for getUpdates long polling
        self._update_offset: int = 0
        self._poll_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def _base_url(self) -> str:
        return f"{self._api_base}/bot{self._token}"

    def submit(self, request: ApprovalRequest) -> None:
        with self._lock:
            self._pending[request.request_id] = request
            self._events[request.request_id] = threading.Event()

        # Build inline keyboard
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✅ Approve", "callback_data": f"approve:{request.request_id}"},
                    {"text": "❌ Deny", "callback_data": f"deny:{request.request_id}"},
                ]
            ]
        }

        text = (
            f"🛡️ *APPROVE REQUIRED*\n\n"
            f"**Tool:** `{request.tool_name}`\n"
            f"**Rule:** `{request.rule_id}`\n"
            f"**Message:** {request.message}\n"
            f"**Session:** `{request.session_id}`\n"
            f"**Request ID:** `{request.request_id[:8]}…`"
        )

        try:
            resp = self._client.post(
                f"{self._base_url}/sendMessage",
                json={
                    "chat_id": self._chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                    "reply_markup": keyboard,
                },
            )
            data = resp.json()
            if data.get("ok"):
                msg_id = data["result"]["message_id"]
                with self._lock:
                    self._message_ids[request.request_id] = msg_id
        except Exception:
            logger.exception("Failed to send Telegram approval request")
        finally:
            # Always start polling — even if message send failed,
            # so the request can be resolved via respond() API
            self._ensure_polling()

    def wait_for_response(self, request_id: str, timeout: float = 300.0) -> ApprovalResponse | None:
        event = self._events.get(request_id)
        if event is None:
            return None
        signaled = event.wait(timeout=timeout)
        if not signaled:
            return None
        with self._lock:
            # Clean up after consuming the response
            self._events.pop(request_id, None)
            return self._responses.pop(request_id, None)

    def respond(
        self,
        request_id: str,
        approved: bool,
        responder: str = "",
        comment: str = "",
    ) -> None:
        response = ApprovalResponse(
            request_id=request_id,
            approved=approved,
            responder=responder,
            comment=comment,
        )
        with self._lock:
            self._responses[request_id] = response
            self._pending.pop(request_id, None)
            self._message_ids.pop(request_id, None)
            event = self._events.get(request_id)
        if event is not None:
            event.set()

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            return list(self._pending.values())

    def health(self) -> dict:
        """Check Telegram Bot API health via getMe."""
        from time import monotonic

        start = monotonic()
        try:
            resp = self._client.get(f"{self._base_url}/getMe", timeout=5.0)
            latency = (monotonic() - start) * 1000
            data = resp.json()
            if data.get("ok"):
                return {"healthy": True, "latency_ms": round(latency, 1), "error": None}
            return {"healthy": False, "latency_ms": round(latency, 1), "error": "getMe returned ok=false"}
        except Exception as e:
            latency = (monotonic() - start) * 1000
            return {"healthy": False, "latency_ms": round(latency, 1), "error": str(e)}

    def stop(self) -> None:
        """Stop the polling thread."""
        self._stop_event.set()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5.0)
        self._client.close()

    def _ensure_polling(self) -> None:
        if self._poll_thread is not None and self._poll_thread.is_alive():
            return
        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._process_updates()
            except Exception:
                logger.exception("Error polling Telegram updates")
            self._stop_event.wait(self._poll_interval)

    def _process_updates(self) -> None:
        try:
            resp = self._client.get(
                f"{self._base_url}/getUpdates",
                params={"offset": self._update_offset, "timeout": 1},
            )
            data = resp.json()
        except Exception:
            return

        if not data.get("ok"):
            return

        for update in data.get("result", []):
            self._update_offset = update["update_id"] + 1
            cb = update.get("callback_query")
            if cb is None:
                continue

            cb_data = cb.get("data", "")
            if ":" not in cb_data:
                continue

            action, request_id = cb_data.split(":", 1)
            if request_id not in self._pending and request_id not in self._events:
                continue

            approved = action == "approve"
            responder = cb.get("from", {}).get("username", "telegram")

            self.respond(request_id, approved=approved, responder=responder)

            # Answer callback to remove loading state
            try:
                self._client.post(
                    f"{self._base_url}/answerCallbackQuery",
                    json={
                        "callback_query_id": cb["id"],
                        "text": "✅ Approved" if approved else "❌ Denied",
                    },
                )
            except Exception:
                pass

            # Check if no more pending
            with self._lock:
                if not self._pending:
                    self._stop_event.set()
