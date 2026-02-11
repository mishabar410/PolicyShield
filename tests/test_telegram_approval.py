"""Tests for TelegramApprovalBackend."""

from __future__ import annotations

from unittest.mock import MagicMock


from policyshield.approval.base import ApprovalRequest
from policyshield.approval.telegram import TelegramApprovalBackend


def _make_request(**overrides) -> ApprovalRequest:
    return ApprovalRequest.create(
        tool_name=overrides.get("tool_name", "exec"),
        args=overrides.get("args", {"cmd": "test"}),
        rule_id=overrides.get("rule_id", "rule-1"),
        message=overrides.get("message", "Needs approval"),
        session_id=overrides.get("session_id", "s1"),
    )


class FakeHttpResponse:
    """Fake httpx.Response."""

    def __init__(self, data: dict):
        self._data = data

    def json(self):
        return self._data


class TestTelegramBackendUnit:
    """Unit tests with mocked HTTP client."""

    def _make_backend(self):
        backend = TelegramApprovalBackend(
            bot_token="test-token",
            chat_id="12345",
            poll_interval=0.05,
        )
        backend._client = MagicMock()
        return backend

    def test_submit_sends_message(self):
        backend = self._make_backend()
        backend._client.post.return_value = FakeHttpResponse(
            {"ok": True, "result": {"message_id": 42}}
        )
        backend._client.get.return_value = FakeHttpResponse({"ok": True, "result": []})

        req = _make_request()
        backend.submit(req)

        # Verify sendMessage was called
        call_args = backend._client.post.call_args
        assert "/sendMessage" in call_args[0][0]
        body = call_args[1]["json"]
        assert body["chat_id"] == "12345"
        assert "APPROVE REQUIRED" in body["text"]
        assert body["reply_markup"]["inline_keyboard"] is not None

        backend.stop()

    def test_submit_stores_pending(self):
        backend = self._make_backend()
        backend._client.post.return_value = FakeHttpResponse(
            {"ok": True, "result": {"message_id": 42}}
        )
        backend._client.get.return_value = FakeHttpResponse({"ok": True, "result": []})

        req = _make_request()
        backend.submit(req)
        assert len(backend.pending()) == 1
        backend.stop()

    def test_respond_sets_event(self):
        backend = self._make_backend()
        backend._client.post.return_value = FakeHttpResponse(
            {"ok": True, "result": {"message_id": 42}}
        )
        backend._client.get.return_value = FakeHttpResponse({"ok": True, "result": []})

        req = _make_request()
        backend.submit(req)

        backend.respond(req.request_id, approved=True, responder="admin")
        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp is not None
        assert resp.approved is True
        backend.stop()

    def test_timeout_returns_none(self):
        backend = self._make_backend()
        backend._client.post.return_value = FakeHttpResponse(
            {"ok": True, "result": {"message_id": 42}}
        )
        backend._client.get.return_value = FakeHttpResponse({"ok": True, "result": []})

        req = _make_request()
        backend.submit(req)
        resp = backend.wait_for_response(req.request_id, timeout=0.1)
        assert resp is None
        backend.stop()

    def test_process_updates_approve(self):
        backend = self._make_backend()
        backend._client.post.return_value = FakeHttpResponse(
            {"ok": True, "result": {"message_id": 42}}
        )
        backend._client.get.return_value = FakeHttpResponse({"ok": True, "result": []})

        req = _make_request()
        backend.submit(req)
        backend._stop_event.set()  # Stop auto-polling so we can control it

        import time
        time.sleep(0.1)

        # Simulate callback query
        backend._client.get.return_value = FakeHttpResponse({
            "ok": True,
            "result": [{
                "update_id": 1,
                "callback_query": {
                    "id": "cb1",
                    "data": f"approve:{req.request_id}",
                    "from": {"username": "testuser"},
                },
            }],
        })
        backend._client.post.return_value = FakeHttpResponse({"ok": True})

        backend._process_updates()

        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp is not None
        assert resp.approved is True
        assert resp.responder == "testuser"
        backend.stop()

    def test_process_updates_deny(self):
        backend = self._make_backend()
        backend._client.post.return_value = FakeHttpResponse(
            {"ok": True, "result": {"message_id": 42}}
        )
        backend._client.get.return_value = FakeHttpResponse({"ok": True, "result": []})

        req = _make_request()
        backend.submit(req)
        backend._stop_event.set()

        import time
        time.sleep(0.1)

        backend._client.get.return_value = FakeHttpResponse({
            "ok": True,
            "result": [{
                "update_id": 2,
                "callback_query": {
                    "id": "cb2",
                    "data": f"deny:{req.request_id}",
                    "from": {"username": "admin"},
                },
            }],
        })
        backend._client.post.return_value = FakeHttpResponse({"ok": True})

        backend._process_updates()

        resp = backend.wait_for_response(req.request_id, timeout=1.0)
        assert resp is not None
        assert resp.approved is False
        backend.stop()

    def test_multiple_pending(self):
        backend = self._make_backend()
        backend._client.post.return_value = FakeHttpResponse(
            {"ok": True, "result": {"message_id": 42}}
        )
        backend._client.get.return_value = FakeHttpResponse({"ok": True, "result": []})

        for i in range(3):
            backend.submit(_make_request(tool_name=f"tool-{i}"))
        assert len(backend.pending()) == 3
        backend.stop()

    def test_send_failure_graceful(self):
        backend = self._make_backend()
        backend._client.post.side_effect = Exception("Network error")
        backend._client.get.return_value = FakeHttpResponse({"ok": True, "result": []})

        req = _make_request()
        # Should not raise
        backend.submit(req)
        # Still pending even though send failed
        assert len(backend.pending()) == 1
        backend.stop()
