"""Approval backends for human-in-the-loop workflows."""

from policyshield.approval.base import ApprovalBackend, ApprovalRequest, ApprovalResponse
from policyshield.approval.cli_backend import CLIBackend
from policyshield.approval.memory import InMemoryBackend
from policyshield.approval.telegram import TelegramApprovalBackend

__all__ = [
    "ApprovalBackend",
    "ApprovalRequest",
    "ApprovalResponse",
    "CLIBackend",
    "InMemoryBackend",
    "TelegramApprovalBackend",
]
