"""Approval backends for human-in-the-loop workflows."""

from __future__ import annotations

from typing import TYPE_CHECKING

from policyshield.approval.base import ApprovalBackend, ApprovalRequest, ApprovalResponse
from policyshield.approval.cli_backend import CLIBackend
from policyshield.approval.memory import InMemoryBackend

if TYPE_CHECKING:
    from policyshield.approval.telegram import TelegramApprovalBackend
    from policyshield.approval.webhook import (
        WebhookApprovalBackend,
        compute_signature,
        verify_signature,
    )

__all__ = [
    "ApprovalBackend",
    "ApprovalRequest",
    "ApprovalResponse",
    "CLIBackend",
    "InMemoryBackend",
    "TelegramApprovalBackend",
    "WebhookApprovalBackend",
    "compute_signature",
    "verify_signature",
]


_WEBHOOK_NAMES = {"WebhookApprovalBackend", "compute_signature", "verify_signature"}


def __getattr__(name: str):  # noqa: ANN001
    if name == "TelegramApprovalBackend":
        from policyshield.approval.telegram import TelegramApprovalBackend

        return TelegramApprovalBackend
    if name in _WEBHOOK_NAMES:
        from policyshield.approval import webhook as _wh

        return getattr(_wh, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
