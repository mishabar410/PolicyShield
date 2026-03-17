"""Approval backend models and abstract base class."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class ApprovalRequest:
    """A request for human approval."""

    request_id: str
    tool_name: str
    args: dict
    rule_id: str
    message: str
    session_id: str
    timestamp: datetime

    @staticmethod
    def create(
        tool_name: str,
        args: dict,
        rule_id: str,
        message: str,
        session_id: str,
    ) -> ApprovalRequest:
        """Factory to create a new request with auto-generated ID and timestamp."""
        return ApprovalRequest(
            request_id=str(uuid.uuid4()),
            tool_name=tool_name,
            args=args,
            rule_id=rule_id,
            message=message,
            session_id=session_id,
            timestamp=datetime.now(timezone.utc),
        )


@dataclass(frozen=True)
class ApprovalResponse:
    """Human response to an approval request."""

    request_id: str
    approved: bool
    responder: str = ""
    comment: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ApprovalBackend(ABC):
    """Abstract base for approval backends."""

    @abstractmethod
    def submit(self, request: ApprovalRequest) -> None:
        """Submit an approval request."""

    @abstractmethod
    def wait_for_response(self, request_id: str, timeout: float = 300.0) -> ApprovalResponse | None:
        """Wait for a response to an approval request.

        Returns None on timeout.
        """

    @abstractmethod
    def respond(
        self,
        request_id: str,
        approved: bool,
        responder: str = "",
        comment: str = "",
    ) -> None:
        """Submit a response to an approval request."""

    @abstractmethod
    def pending(self) -> list[ApprovalRequest]:
        """Return all pending (unanswered) requests."""

    def health(self) -> dict:
        """Check backend health. Override in subclasses.

        Returns:
            dict with 'healthy' (bool), 'latency_ms' (float), 'error' (str|None)
        """
        return {"healthy": True, "latency_ms": 0, "error": None}
