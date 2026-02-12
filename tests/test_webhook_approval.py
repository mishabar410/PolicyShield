"""Tests for WebhookApprovalBackend."""

import hashlib
import hmac
from datetime import datetime, timezone

import httpx

from policyshield.approval.base import ApprovalRequest
from policyshield.approval.webhook import (
    WebhookApprovalBackend,
    compute_signature,
    verify_signature,
)


def _make_request(**overrides) -> ApprovalRequest:
    defaults = dict(
        request_id="req-1",
        tool_name="web_search",
        args={"query": "test"},
        rule_id="r1",
        message="Needs approval",
        session_id="sess-1",
        timestamp=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return ApprovalRequest(**defaults)


def _make_backend(handler, **kwargs) -> WebhookApprovalBackend:
    """Create a backend with a mock transport by patching _sync/_poll."""
    transport = httpx.MockTransport(handler)
    backend = WebhookApprovalBackend(**kwargs)
    backend._mock_transport = transport
    return backend


# Monkey-patch the webhook to use mock transport — override _build_client
# Better: just patch at a low level. For simplicity, we'll override
# httpx.Client in the webhook module directly.


def _patched_submit(backend, request):
    """Run submit using mock transport."""
    import policyshield.approval.webhook as wmod

    original_client = httpx.Client

    class MockClient(httpx.Client):
        def __init__(self, **kwargs):
            kwargs.pop("timeout", None)
            super().__init__(transport=backend._mock_transport, **kwargs)

    wmod.httpx.Client = MockClient
    try:
        # Call original submit
        WebhookApprovalBackend.submit(backend, request)
    finally:
        wmod.httpx.Client = original_client


# ── Test 1: sync → approved ──────────────────────────────────────────


def test_sync_approved():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"approved": True, "reason": "ok"})

    backend = _make_backend(handler, webhook_url="https://example.com/webhook")
    req = _make_request()
    _patched_submit(backend, req)
    resp = backend.wait_for_response("req-1")

    assert resp is not None
    assert resp.approved is True


# ── Test 2: sync → denied ───────────────────────────────────────────


def test_sync_denied():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"approved": False, "reason": "nope"})

    backend = _make_backend(handler, webhook_url="https://example.com/webhook")
    _patched_submit(backend, _make_request())
    resp = backend.wait_for_response("req-1")

    assert resp is not None
    assert resp.approved is False


# ── Test 3: sync → HTTP error ───────────────────────────────────────


def test_sync_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "internal"})

    backend = _make_backend(handler, webhook_url="https://example.com/webhook")
    _patched_submit(backend, _make_request())
    resp = backend.wait_for_response("req-1")

    assert resp is not None
    assert resp.approved is False
    assert "500" in resp.comment


# ── Test 4: sync → timeout ──────────────────────────────────────────


def test_sync_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    backend = _make_backend(handler, webhook_url="https://example.com/webhook", timeout=0.1)
    _patched_submit(backend, _make_request())
    resp = backend.wait_for_response("req-1")

    assert resp is not None
    assert resp.approved is False
    assert "timeout" in resp.comment


# ── Test 5: HMAC signature sent ─────────────────────────────────────


def test_sync_hmac_signature():
    captured_headers: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json={"approved": True})

    backend = _make_backend(handler, webhook_url="https://example.com/webhook", secret="my-secret")
    _patched_submit(backend, _make_request())

    assert "x-policyshield-signature" in captured_headers
    assert captured_headers["x-policyshield-signature"].startswith("sha256=")


# ── Test 6: no secret → no signature header ─────────────────────────


def test_sync_no_secret():
    captured_headers: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json={"approved": True})

    backend = _make_backend(handler, webhook_url="https://example.com/webhook")
    _patched_submit(backend, _make_request())

    assert "x-policyshield-signature" not in captured_headers


# ── Test 7: custom headers ──────────────────────────────────────────


def test_sync_custom_headers():
    captured_headers: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json={"approved": True})

    backend = _make_backend(
        handler,
        webhook_url="https://example.com/webhook",
        headers={"X-Custom": "value"},
    )
    _patched_submit(backend, _make_request())

    assert captured_headers.get("x-custom") == "value"


# ── Test 8: poll → approved ─────────────────────────────────────────


def test_poll_approved():
    poll_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal poll_count
        if request.method == "POST":
            return httpx.Response(200, json={"poll_url": "https://example.com/poll/1"})
        poll_count += 1
        if poll_count >= 2:
            return httpx.Response(200, json={"status": "approved", "reason": "ok"})
        return httpx.Response(200, json={"status": "pending"})

    backend = _make_backend(
        handler,
        webhook_url="https://example.com/webhook",
        mode="poll",
        poll_interval=0.01,
        poll_timeout=5.0,
    )
    _patched_submit(backend, _make_request())
    resp = backend.wait_for_response("req-1")

    assert resp is not None
    assert resp.approved is True


# ── Test 9: poll → denied ───────────────────────────────────────────


def test_poll_denied():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"poll_url": "https://example.com/poll/1"})
        return httpx.Response(200, json={"status": "denied", "reason": "no"})

    backend = _make_backend(
        handler,
        webhook_url="https://example.com/webhook",
        mode="poll",
        poll_interval=0.01,
    )
    _patched_submit(backend, _make_request())
    resp = backend.wait_for_response("req-1")

    assert resp is not None
    assert resp.approved is False


# ── Test 10: poll → timeout ─────────────────────────────────────────


def test_poll_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, json={"poll_url": "https://example.com/poll/1"})
        return httpx.Response(200, json={"status": "pending"})

    backend = _make_backend(
        handler,
        webhook_url="https://example.com/webhook",
        mode="poll",
        poll_interval=0.01,
        poll_timeout=0.05,
    )
    _patched_submit(backend, _make_request())
    resp = backend.wait_for_response("req-1")

    assert resp is not None
    assert resp.approved is False
    assert "timeout" in resp.comment


# ── Test 11: compute_signature ──────────────────────────────────────


def test_compute_signature():
    payload = b'{"test": "data"}'
    secret = "my-secret"
    sig = compute_signature(payload, secret)

    assert sig.startswith("sha256=")
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


# ── Test 12: verify_signature ───────────────────────────────────────


def test_verify_signature():
    payload = b'{"test": "data"}'
    secret = "my-secret"
    sig = compute_signature(payload, secret)

    assert verify_signature(payload, secret, sig) is True
    assert verify_signature(payload, secret, "sha256=wrong") is False
    assert verify_signature(b"different", secret, sig) is False
