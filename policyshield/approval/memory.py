"""In-memory approval backend for testing and simple use cases."""

from __future__ import annotations

import threading

from policyshield.approval.base import (
    ApprovalBackend,
    ApprovalRequest,
    ApprovalResponse,
)


class InMemoryBackend(ApprovalBackend):
    """In-memory approval backend using threading.Event for blocking waits."""

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._responses: dict[str, ApprovalResponse] = {}
        self._events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def submit(self, request: ApprovalRequest) -> None:
        with self._lock:
            self._requests[request.request_id] = request
            self._events[request.request_id] = threading.Event()

    def wait_for_response(self, request_id: str, timeout: float = 300.0) -> ApprovalResponse | None:
        event = self._events.get(request_id)
        if event is None:
            return None

        signaled = event.wait(timeout=timeout)
        if not signaled:
            return None

        with self._lock:
            return self._responses.get(request_id)

    def respond(
        self,
        request_id: str,
        approved: bool,
        responder: str = "",
        comment: str = "",
    ) -> None:
        with self._lock:
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
