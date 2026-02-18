"""In-memory approval backend for testing and simple use cases."""

from __future__ import annotations

import logging
import threading
from time import monotonic

from policyshield.approval.base import (
    ApprovalBackend,
    ApprovalRequest,
    ApprovalResponse,
)

logger = logging.getLogger(__name__)


class InMemoryBackend(ApprovalBackend):
    """In-memory approval backend using threading.Event for blocking waits.

    Features:
        - Approval timeout with auto-resolution (BLOCK/ALLOW)
        - First-response-wins guard for concurrent approvals
        - Periodic garbage collection of stale entries
    """

    def __init__(
        self,
        timeout: float = 300.0,
        on_timeout: str = "BLOCK",
        gc_ttl: float = 3600.0,
        gc_interval: float = 60.0,
    ) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._responses: dict[str, ApprovalResponse] = {}
        self._events: dict[str, threading.Event] = {}
        self._created_at: dict[str, float] = {}
        self._lock = threading.Lock()
        self._timeout = timeout
        self._on_timeout = on_timeout
        self._gc_ttl = gc_ttl
        self._gc_interval = gc_interval
        self._gc_timer: threading.Timer | None = None
        self._start_gc()

    # ── GC ────────────────────────────────────────────────────────

    def _start_gc(self) -> None:
        """Start periodic garbage collection."""
        self._gc_timer = threading.Timer(self._gc_interval, self._run_gc)
        self._gc_timer.daemon = True
        self._gc_timer.start()

    def _run_gc(self) -> None:
        """Remove entries older than gc_ttl."""
        now = monotonic()
        with self._lock:
            expired = [k for k, ts in self._created_at.items() if now - ts > self._gc_ttl]
            for k in expired:
                self._requests.pop(k, None)
                self._responses.pop(k, None)
                self._created_at.pop(k, None)
                self._events.pop(k, None)
            if expired:
                logger.info("GC: cleaned %d stale approvals", len(expired))
        self._start_gc()  # Reschedule

    # ── Core API ──────────────────────────────────────────────────

    def submit(self, request: ApprovalRequest) -> None:
        with self._lock:
            self._requests[request.request_id] = request
            self._events[request.request_id] = threading.Event()
            self._created_at[request.request_id] = monotonic()

    def get_status(self, request_id: str) -> dict:
        """Check status of a request, including timeout detection."""
        with self._lock:
            if request_id in self._responses:
                resp = self._responses[request_id]
                return {
                    "status": "approved" if resp.approved else "denied",
                    "responder": resp.responder,
                    "approved": resp.approved,
                }
            if request_id in self._created_at:
                elapsed = monotonic() - self._created_at[request_id]
                if elapsed > self._timeout:
                    return {
                        "status": "timeout",
                        "elapsed": elapsed,
                        "auto_verdict": self._on_timeout,
                    }
            return {"status": "pending", "responder": None}

    def wait_for_response(self, request_id: str, timeout: float = 300.0) -> ApprovalResponse | None:
        event = self._events.get(request_id)
        if event is None:
            return None

        signaled = event.wait(timeout=timeout)
        if not signaled:
            return None

        with self._lock:
            # Clean up event after consuming the response
            self._events.pop(request_id, None)
            return self._responses.pop(request_id, None)

    def respond(
        self,
        request_id: str,
        approved: bool,
        responder: str = "",
        comment: str = "",
    ) -> None:
        with self._lock:
            # Guard: unknown approval
            if request_id not in self._requests and request_id not in self._events:
                logger.warning("Response for unknown approval %s", request_id)
                return
            # Guard: first-response-wins
            if request_id in self._responses:
                logger.info(
                    "Duplicate response for %s from %s ignored (first response from %s wins)",
                    request_id,
                    responder,
                    self._responses[request_id].responder,
                )
                return

            self._responses[request_id] = ApprovalResponse(
                request_id=request_id,
                approved=approved,
                responder=responder,
                comment=comment,
            )
            # Remove from pending
            self._requests.pop(request_id, None)

            event = self._events.get(request_id)
        if event is not None:
            event.set()

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            return list(self._requests.values())

    def stop(self) -> None:
        """Clean up all pending state and stop GC timer (called during shutdown)."""
        if self._gc_timer:
            self._gc_timer.cancel()
            self._gc_timer = None
        with self._lock:
            self._requests.clear()
            self._responses.clear()
            self._created_at.clear()
            # Signal all waiting threads so they unblock
            for event in self._events.values():
                event.set()
            self._events.clear()
