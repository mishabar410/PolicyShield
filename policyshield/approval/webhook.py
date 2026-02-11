"""Webhook-based approval backend for PolicyShield.

Sends approval requests via HTTP POST to a configurable webhook URL,
with optional HMAC-SHA256 signing for verification.

Two modes:
- **sync**: POST → immediate JSON response with ``approved`` field.
- **poll**: POST → receive ``poll_url``, then GET-poll until resolved.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Literal

import httpx

from policyshield.approval.base import (
    ApprovalBackend,
    ApprovalRequest,
    ApprovalResponse,
)

logger = logging.getLogger("policyshield")


def compute_signature(payload: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for *payload* using *secret*.

    Returns:
        Hex-encoded signature string prefixed with ``sha256=``.
    """
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def verify_signature(payload: bytes, secret: str, signature: str) -> bool:
    """Verify HMAC-SHA256 *signature* (constant-time comparison).

    Args:
        payload: Raw request body.
        secret: Shared secret.
        signature: Value from ``X-PolicyShield-Signature`` header.

    Returns:
        True if the signature is valid.
    """
    expected = compute_signature(payload, secret)
    return hmac.compare_digest(expected, signature)


class WebhookApprovalBackend(ApprovalBackend):
    """Send approval requests via HTTP webhook.

    Flow:
        1. POST request to ``webhook_url`` with approval details.
        2. In **sync** mode the webhook must respond with JSON
           ``{"approved": true/false, "reason": "..."}``.
        3. In **poll** mode the webhook responds with ``{"poll_url": "..."}``
           and the backend polls until a terminal status appears.

    Security:
        - HMAC-SHA256 signature in ``X-PolicyShield-Signature`` header.
        - Optional shared secret for webhook verification.
    """

    def __init__(
        self,
        webhook_url: str,
        secret: str | None = None,
        timeout: float = 30.0,
        mode: Literal["sync", "poll"] = "sync",
        poll_interval: float = 2.0,
        poll_timeout: float = 300.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._url = webhook_url
        self._secret = secret
        self._timeout = timeout
        self._mode = mode
        self._poll_interval = poll_interval
        self._poll_timeout = poll_timeout
        self._extra_headers = headers or {}

        # Internal storage to satisfy ApprovalBackend ABC
        self._requests: dict[str, ApprovalRequest] = {}
        self._responses: dict[str, ApprovalResponse] = {}

    # ── ABC implementation ───────────────────────────────────────────

    def submit(self, request: ApprovalRequest) -> None:
        """Submit an approval request via webhook."""
        self._requests[request.request_id] = request

        if self._mode == "sync":
            resp = self._sync_request(request)
        else:
            resp = self._poll_request(request)

        self._responses[request.request_id] = resp

    def wait_for_response(
        self,
        request_id: str,
        timeout: float = 300.0,  # noqa: ARG002
    ) -> ApprovalResponse | None:
        """Return stored response (already resolved during submit)."""
        return self._responses.get(request_id)

    def respond(
        self,
        request_id: str,
        approved: bool,
        responder: str = "",
        comment: str = "",
    ) -> None:
        """Manually inject a response (for testing / external callbacks)."""
        self._responses[request_id] = ApprovalResponse(
            request_id=request_id,
            approved=approved,
            responder=responder,
            comment=comment,
        )

    def pending(self) -> list[ApprovalRequest]:
        """Return requests with no response yet."""
        return [
            r for rid, r in self._requests.items()
            if rid not in self._responses
        ]

    # ── Internal helpers ─────────────────────────────────────────────

    def _build_payload(self, request: ApprovalRequest) -> dict[str, Any]:
        return {
            "request_id": request.request_id,
            "tool": request.tool_name,
            "args": request.args,
            "rule_id": request.rule_id,
            "message": request.message,
            "session_id": request.session_id,
            "timestamp": request.timestamp.isoformat(),
        }

    def _build_headers(self, body: bytes) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            **self._extra_headers,
        }
        if self._secret:
            headers["X-PolicyShield-Signature"] = compute_signature(body, self._secret)
        return headers

    def _sync_request(self, request: ApprovalRequest) -> ApprovalResponse:
        """Send POST and expect immediate JSON answer."""
        payload = self._build_payload(request)
        body = json.dumps(payload).encode()
        headers = self._build_headers(body)

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(self._url, content=body, headers=headers)

            if resp.status_code >= 400:
                return ApprovalResponse(
                    request_id=request.request_id,
                    approved=False,
                    comment=f"webhook error: HTTP {resp.status_code}",
                )

            data = resp.json()
            return ApprovalResponse(
                request_id=request.request_id,
                approved=bool(data.get("approved", False)),
                comment=data.get("reason", ""),
            )
        except httpx.TimeoutException:
            return ApprovalResponse(
                request_id=request.request_id,
                approved=False,
                comment="webhook timeout",
            )
        except Exception as e:
            logger.warning("Webhook request failed: %s", e)
            return ApprovalResponse(
                request_id=request.request_id,
                approved=False,
                comment=f"webhook error: {e}",
            )

    def _poll_request(self, request: ApprovalRequest) -> ApprovalResponse:
        """Send POST, get poll_url, then poll until resolved."""
        payload = self._build_payload(request)
        body = json.dumps(payload).encode()
        headers = self._build_headers(body)

        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(self._url, content=body, headers=headers)

            if resp.status_code >= 400:
                return ApprovalResponse(
                    request_id=request.request_id,
                    approved=False,
                    comment=f"webhook error: HTTP {resp.status_code}",
                )

            data = resp.json()
            poll_url = data.get("poll_url")
            if not poll_url:
                return ApprovalResponse(
                    request_id=request.request_id,
                    approved=False,
                    comment="webhook error: no poll_url in response",
                )

        except Exception as e:
            return ApprovalResponse(
                request_id=request.request_id,
                approved=False,
                comment=f"webhook error: {e}",
            )

        # Poll loop
        deadline = time.monotonic() + self._poll_timeout
        while time.monotonic() < deadline:
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    poll_resp = client.get(poll_url, headers=self._extra_headers)
                poll_data = poll_resp.json()
                status = poll_data.get("status", "pending")

                if status == "approved":
                    return ApprovalResponse(
                        request_id=request.request_id,
                        approved=True,
                        comment=poll_data.get("reason", ""),
                    )
                if status == "denied":
                    return ApprovalResponse(
                        request_id=request.request_id,
                        approved=False,
                        comment=poll_data.get("reason", ""),
                    )

                # Still pending
                time.sleep(self._poll_interval)

            except Exception as e:
                logger.warning("Poll request failed: %s", e)
                time.sleep(self._poll_interval)

        # Timed out
        return ApprovalResponse(
            request_id=request.request_id,
            approved=False,
            comment="poll timeout",
        )
